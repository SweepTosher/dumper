import frida
import json
import msgpack
import sys
import os
import time
import base64
from datetime import datetime

DUMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dumps")
PROCESS_NAME = "UmamusumePrettyDerby.exe"

class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            try:
                return obj.decode('utf-8')
            except Exception:
                return "b64:" + base64.b64encode(obj).decode('ascii')
        return super().default(obj)

HOOK_JS = r"""
var ga = Process.findModuleByName('GameAssembly.dll');
if (ga) {
    var il2cpp_domain_get = new NativeFunction(
        ga.findExportByName('il2cpp_domain_get'), 'pointer', []);
    var il2cpp_domain_get_assemblies = new NativeFunction(
        ga.findExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer', 'pointer']);
    var il2cpp_assembly_get_image = new NativeFunction(
        ga.findExportByName('il2cpp_assembly_get_image'), 'pointer', ['pointer']);
    var il2cpp_class_from_name = new NativeFunction(
        ga.findExportByName('il2cpp_class_from_name'), 'pointer', ['pointer', 'pointer', 'pointer']);
    var il2cpp_class_get_method_from_name = new NativeFunction(
        ga.findExportByName('il2cpp_class_get_method_from_name'), 'pointer', ['pointer', 'pointer', 'int']);
    var il2cpp_array_length_fn = new NativeFunction(
        ga.findExportByName('il2cpp_array_length'), 'uint', ['pointer']);

    var il2cpp_array_addr = null;
    var arrayAddrExport = ga.findExportByName('il2cpp_array_addr_with_size');
    if (arrayAddrExport) {
        il2cpp_array_addr = new NativeFunction(arrayAddrExport, 'pointer', ['pointer', 'int', 'uint']);
    }

    var domain = il2cpp_domain_get();
    var sizeOut = Memory.alloc(4);
    var assemblies = il2cpp_domain_get_assemblies(domain, sizeOut);
    var assemblyCount = sizeOut.readU32();

    var nsPtr = Memory.allocUtf8String('Gallop');
    var cnPtr = Memory.allocUtf8String('HttpHelper');
    var foundClass = null;

    for (var i = 0; i < assemblyCount && !foundClass; i++) {
        var assembly = assemblies.add(i * Process.pointerSize).readPointer();
        var image = il2cpp_assembly_get_image(assembly);
        var klass = il2cpp_class_from_name(image, nsPtr, cnPtr);
        if (!klass.isNull()) {
            foundClass = klass;
        }
    }

    if (foundClass) {
        function readManagedArray(arr) {
            var len = il2cpp_array_length_fn(arr);
            if (len <= 0 || len > 50 * 1024 * 1024) return null;
            var dataPtr = il2cpp_array_addr
                ? il2cpp_array_addr(arr, 1, 0)
                : arr.add(0x20);
            return dataPtr.readByteArray(len);
        }

        var decompName = Memory.allocUtf8String('DecompressResponse');
        var decompMethod = il2cpp_class_get_method_from_name(foundClass, decompName, 1);
        if (!decompMethod.isNull()) {
            Interceptor.attach(decompMethod.readPointer(), {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        try {
                            var data = readManagedArray(retval);
                            if (data) send({t: 'R'}, data);
                        } catch(e) {}
                    }
                }
            });
        }

        var compName = Memory.allocUtf8String('CompressRequest');
        var compMethod = il2cpp_class_get_method_from_name(foundClass, compName, 1);
        if (!compMethod.isNull()) {
            Interceptor.attach(compMethod.readPointer(), {
                onEnter: function(args) {
                    try {
                        var data = readManagedArray(args[0]);
                        if (data) send({t: 'Q'}, data);
                    } catch(e) {
                        try {
                            var data2 = readManagedArray(args[1]);
                            if (data2) send({t: 'Q'}, data2);
                        } catch(e2) {}
                    }
                }
            });
        }
    }
}
"""

def decodeMsgpack(data, is_request=False):
    raw = bytes(data)
    try:
        return msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except Exception:
        pass
    if is_request and len(raw) >= 4:
        offset = int.from_bytes(raw[:4], 'little')
        header_size = 4 + offset
        if 0 < header_size < len(raw):
            try:
                return msgpack.unpackb(raw[header_size:], raw=False, strict_map_key=False)
            except Exception:
                pass
    return None

def onMessage(message, data):
    if message['type'] != 'send' or data is None:
        return

    ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    is_request = message['payload']['t'] == 'Q'
    kind = "request" if is_request else "response"

    decoded = decodeMsgpack(data, is_request)
    if decoded is None:
        return 

    with open(os.path.join(DUMP_DIR, f"{ts}_{kind}.json"), 'w', encoding='utf-8') as f:
        json.dump(decoded, f, indent=2, ensure_ascii=False, cls=BytesEncoder)

def main():
    os.makedirs(DUMP_DIR, exist_ok=True)
    try:
        session = frida.attach(PROCESS_NAME)
    except Exception:
        return 1

    script = session.create_script(HOOK_JS)
    script.on('message', onMessage)
    script.load()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    session.detach()
    return 0

if __name__ == "__main__":
    sys.exit(main())