import frida
import json
import msgpack
import os
import time
import threading
import queue
import sqlite3
import tkinter as tk

PROCESS_NAME = "UmamusumePrettyDerby.exe"
OUTCOMES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outcomes.json")
MDB_PATH = os.path.expanduser('~/AppData/LocalLow/Cygames/Umamusume/master/master.mdb')

IGNORE_KEYS = {"single_mode_chara_id", "card_id", "chara_grade", "race_program_id", "reserve_race_program_id", "turn", "start_time", "succession_trained_chara_id_1", "succession_trained_chara_id_2"}

state_lock = threading.Lock()
current_event_state = {
    "event_name": None,
    "choice_map": {}, 
    "chara_info_before": None,
    "pending_selected_choice_num": None,
    "pending_select_index": None
}

ui_queue = queue.Queue()

def broadcast(data: dict):
    ui_queue.put(data)

def build_mdb_cache():
    cache = {}
    if not os.path.exists(MDB_PATH):
        return cache
    try:
        conn = sqlite3.connect(MDB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT "index", text FROM text_data WHERE category=181')
        for idx, text in cursor.fetchall():
            cache[idx] = text
        conn.close()
    except:
        pass
    return cache

mdb_cache = build_mdb_cache()

def load_outcomes():
    if not os.path.exists(OUTCOMES_FILE):
        return {}
    try:
        with open(OUTCOMES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_outcomes(data):
    try:
        with open(OUTCOMES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except:
        pass

outcomes_db = load_outcomes()

def calculate_diff(before, after):
    diff = {}
    for k, v_before in before.items():
        if k in IGNORE_KEYS: continue
        if isinstance(v_before, int):
            v_after = after.get(k)
            if isinstance(v_after, int) and v_after != v_before:
                diff[k] = v_after - v_before
                
    eff_before = set(before.get("chara_effect_id_array", []))
    eff_after = set(after.get("chara_effect_id_array", []))
    gained = list(eff_after - eff_before)
    lost = list(eff_before - eff_after)
    if gained: diff["gained_conditions"] = gained
    if lost: diff["lost_conditions"] = lost
    
    tips_before = {tip["group_id"]: tip.get("level", 1) for tip in before.get("skill_tips_array", [])}
    tips_after = {tip["group_id"]: tip.get("level", 1) for tip in after.get("skill_tips_array", [])}
    gained_tips = {}
    for sid, after_lvl in tips_after.items():
        before_lvl = tips_before.get(sid, 0)
        if after_lvl > before_lvl:
            gained_tips[str(sid)] = after_lvl - before_lvl
    if gained_tips:
        diff["gained_skill_hints"] = gained_tips
        
    items = after.get("free_data_set", {}).get("item_effect_array", [])
    if items:
        # just record the item_id for now
        gained_items = [item.get("item_id") for item in items if "item_id" in item]
        if gained_items:
            diff["gained_items"] = gained_items
        
    return diff

def merge_diffs(existing, new_diff):
    merged = existing.copy()
    for k, new_val in new_diff.items():
        if k == "gained_conditions" or k == "lost_conditions":
            existing_list = merged.get(k, [])
            merged[k] = list(set(existing_list + new_val))
        elif k == "gained_skill_hints":
            existing_hints = merged.get(k, {})
            for sid, lvl in new_val.items():
                if sid not in existing_hints or lvl > existing_hints[sid]:
                    existing_hints[sid] = lvl
            merged[k] = existing_hints
        else:
            existing_val = merged.get(k, 0)
            if abs(new_val) > abs(existing_val):
                merged[k] = new_val
    return merged

def format_diff(diff):
    if not diff:
        return "No stat changes"
        
    parts = []
    for k, v in diff.items():
        if k == "gained_conditions":
            parts.append(f"Gain Cond {v}")
        elif k == "lost_conditions":
            parts.append(f"Lose Cond {v}")
        elif k == "gained_skill_hints":
            if len(v) == 1:
                lvl = list(v.values())[0]
                parts.append(f"Skill hint ({lvl})")
            else:
                hints = [f"Skill hint {idx} ({lvl})" for idx, lvl in enumerate(v.values(), 1)]
                parts.append(" | ".join(hints))
        elif k == "gained_items":
            parts.append(f"Gain Items {v}")
        elif k == "motivation":
            sign = "+" if v > 0 else ""
            parts.append(f"Mood{sign}{v}")
        else:
            sign = "+" if v > 0 else ""
            name = k.replace("_", " ").title()
            parts.append(f"{name}{sign}{v}")
    return ", ".join(parts)

def decodeMsgpack(data, is_request=False):
    raw = bytes(data)
    try:
        return msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except:
        pass
    if is_request and len(raw) >= 4:
        offset = int.from_bytes(raw[:4], 'little')
        header_size = 4 + offset
        if 0 < header_size < len(raw):
            try:
                return msgpack.unpackb(raw[header_size:], raw=False, strict_map_key=False)
            except:
                pass
    return None

def process_traffic(decoded, is_request):
    global current_event_state, outcomes_db
    with state_lock:
        if is_request:
            req_payload = decoded.get("payload", decoded) if isinstance(decoded, dict) else {}
            if "choice_number" in req_payload:
                raw_choice = req_payload.get("choice_number")
                if current_event_state["event_name"]:
                    ui_slot = 0 if len(current_event_state["choice_map"]) <= 1 else raw_choice - 1
                    if ui_slot in current_event_state["choice_map"]:
                        current_event_state["pending_selected_choice_num"] = ui_slot
                        current_event_state["pending_select_index"] = current_event_state["choice_map"][ui_slot]
        else:
            if isinstance(decoded, dict) and "data" in decoded and isinstance(decoded["data"], dict):
                data_block = decoded["data"]
                
                chara_info_current = data_block.get("chara_info")
                if chara_info_current and "vital" in chara_info_current and "max_vital" in chara_info_current:
                    broadcast({"status": "energy_update", "vital": chara_info_current["vital"], "max_vital": chara_info_current["max_vital"]})
                
                if "unchecked_event_array" in data_block:
                    unchecked_arr = data_block.get("unchecked_event_array", [])
                    
                    if current_event_state["pending_select_index"] is not None and current_event_state["pending_selected_choice_num"] is not None:
                        chara_info_after = data_block.get("chara_info")
                        if chara_info_after and current_event_state["chara_info_before"]:
                            if len(current_event_state["choice_map"]) > 1:
                                diff = calculate_diff(current_event_state["chara_info_before"], chara_info_after)
                                ev_name = current_event_state["event_name"]
                                cnum_str = str(current_event_state["pending_selected_choice_num"])
                                idx_str = str(current_event_state["pending_select_index"])
                                
                                if ev_name not in outcomes_db: outcomes_db[ev_name] = {}
                                if cnum_str not in outcomes_db[ev_name]: outcomes_db[ev_name][cnum_str] = {}
                                
                                existing_diff = outcomes_db[ev_name][cnum_str].get(idx_str, {})
                                merged_diff = merge_diffs(existing_diff, diff)
                                
                                outcomes_db[ev_name][cnum_str][idx_str] = merged_diff
                                save_outcomes(outcomes_db)
                        
                        current_event_state = {"event_name": None, "choice_map": {}, "chara_info_before": None, "pending_selected_choice_num": None, "pending_select_index": None}
                        broadcast({"status": "waiting"})

                    if unchecked_arr and len(unchecked_arr) > 0:
                        event_info = unchecked_arr[0]
                        story_id = event_info.get("story_id")
                        
                        event_name = mdb_cache.get(story_id, f"Unknown Event {story_id}")
                        
                        choices = event_info.get("event_contents_info", {}).get("choice_array", [])
                        choice_map = {i: c.get("select_index") for i, c in enumerate(choices)}
                        current_event_state = {"event_name": event_name, "choice_map": choice_map, "chara_info_before": data_block.get("chara_info"), "pending_selected_choice_num": None, "pending_select_index": None}
                        
                        db_entry = outcomes_db.get(event_name, {})
                        display_choices = []
                        for ui_slot, select_index in choice_map.items():
                            cnum_str = str(ui_slot)
                            idx_str = str(select_index)
                            
                            outcome_diff = db_entry.get(cnum_str, {}).get(idx_str)
                            if outcome_diff is not None:
                                display_choices.append({"slot": ui_slot + 1, "index": select_index, "status": "mapped", "outcome": format_diff(outcome_diff)})
                            else:
                                display_choices.append({"slot": ui_slot + 1, "index": select_index, "status": "unmapped", "outcome": "Not mapped"})
                        
                        broadcast({"status": "event", "event_name": event_name, "choices": display_choices})

def onMessage(message, data):
    if message['type'] != 'send' or data is None:
        return
    is_request = message['payload']['t'] == 'Q'
    decoded = decodeMsgpack(data, is_request)
    if decoded is not None:
        process_traffic(decoded, is_request)

HOOK_JS = r"""
var ga = Process.findModuleByName('GameAssembly.dll');
if (ga) {
    var il2cpp_domain_get = new NativeFunction(ga.findExportByName('il2cpp_domain_get'), 'pointer', []);
    var il2cpp_domain_get_assemblies = new NativeFunction(ga.findExportByName('il2cpp_domain_get_assemblies'), 'pointer', ['pointer', 'pointer']);
    var il2cpp_assembly_get_image = new NativeFunction(ga.findExportByName('il2cpp_assembly_get_image'), 'pointer', ['pointer']);
    var il2cpp_class_from_name = new NativeFunction(ga.findExportByName('il2cpp_class_from_name'), 'pointer', ['pointer', 'pointer', 'pointer']);
    var il2cpp_class_get_method_from_name = new NativeFunction(ga.findExportByName('il2cpp_class_get_method_from_name'), 'pointer', ['pointer', 'pointer', 'int']);
    var il2cpp_array_length_fn = new NativeFunction(ga.findExportByName('il2cpp_array_length'), 'uint', ['pointer']);

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
        if (!klass.isNull()) { foundClass = klass; }
    }

    if (foundClass) {
        function readManagedArray(arr) {
            var len = il2cpp_array_length_fn(arr);
            if (len <= 0 || len > 50 * 1024 * 1024) return null;
            var dataPtr = il2cpp_array_addr ? il2cpp_array_addr(arr, 1, 0) : arr.add(0x20);
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

def start_frida(ui):
    while True:
        try:
            session = frida.attach(PROCESS_NAME)
            script = session.create_script(HOOK_JS)
            script.on('message', onMessage)
            script.load()
            broadcast({"status": "frida_connected"})
            while True:
                time.sleep(1)
        except:
            time.sleep(5)

class Dumpy(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lil dumpy")
        self.geometry("450x250")
        self.configure(bg="#000000")
        
        self.aot = False
        self.last_html = "WAITING FOR EVENT..."
        
        self.warn_lbl = tk.Label(self, text="Order not guaranteed infer order from results", fg="#ff9800", bg="#000000", font=("Consolas", 8))
        self.warn_lbl.pack(anchor="w", padx=10, pady=(10, 0))
        
        self.energy_var = tk.StringVar()
        self.energy_var.set("Energy: ?/?")
        self.energy_lbl = tk.Label(self, textvariable=self.energy_var, fg="#4caf50", bg="#000000", font=("Consolas", 10, "bold"))
        self.energy_lbl.pack(anchor="w", padx=10, pady=0)
        
        self.text_var = tk.StringVar()
        self.text_var.set(self.last_html)
        self.event_lbl = tk.Label(self, textvariable=self.text_var, fg="white", bg="#000000", font=("Consolas", 10), justify="left")
        self.event_lbl.pack(anchor="w", padx=10, pady=10)
        
        self.btn_aot = tk.Button(self, text="ALWAYS ON TOP: OFF", command=self.toggle_aot, bg="#222222", fg="white", font=("Consolas", 9), relief="solid", bd=1)
        self.btn_aot.pack(anchor="w", padx=10, pady=10)
        
        self.after(100, self.poll_queue)

    def toggle_aot(self):
        self.aot = not self.aot
        self.attributes('-topmost', self.aot)
        self.btn_aot.configure(text=f"ALWAYS ON TOP: {'ON' if self.aot else 'OFF'}")

    def poll_queue(self):
        while not ui_queue.empty():
            msg = ui_queue.get()
            if msg["status"] == "energy_update":
                self.energy_var.set(f"Energy: {msg['vital']}/{msg['max_vital']}")
            elif msg["status"] == "waiting":
                self.text_var.set(self.last_html + "\n\n[WAITING...]")
            elif msg["status"] == "event":
                h = f"> {msg['event_name']}\n"
                if len(msg.get("choices", [])) <= 1:
                    h += "event only has 1 choice\n"
                else:
                    for c in msg["choices"]:
                        out = c["outcome"] if c["status"] == "mapped" else "Not mapped"
                        h += f"Choice {c['slot']} [Idx {c['index']}] {out}\n"
                self.last_html = h.strip()
                self.text_var.set(self.last_html)
        self.after(100, self.poll_queue)

if __name__ == "__main__":
    app = Dumpy()
    threading.Thread(target=start_frida, args=(app,), daemon=True).start()
    app.mainloop()