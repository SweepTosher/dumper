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

CMD_MAPPING = {
    101: ("speed", 1),
    601: ("speed", 1),
    105: ("stamina", 2),
    602: ("stamina", 2),
    102: ("power", 3),
    603: ("power", 3),
    103: ("guts", 4),
    604: ("guts", 4),
    106: ("wit", 5),
    605: ("wit", 5)
}

current_facilities_state = {
    "speed": {"stat": 0, "sp": 0, "energy": 0},
    "stamina": {"stat": 0, "sp": 0, "energy": 0},
    "power": {"stat": 0, "sp": 0, "energy": 0},
    "guts": {"stat": 0, "sp": 0, "energy": 0},
    "wit": {"stat": 0, "sp": 0, "energy": 0}
}

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

def build_mdb_caches():
    story = {}
    cond = {}
    skill = {}
    if not os.path.exists(MDB_PATH):
        return story, cond, skill
    try:
        conn = sqlite3.connect(MDB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT "index", text FROM text_data WHERE category=181')
        for idx, text in cursor.fetchall():
            story[idx] = text
        cursor.execute('SELECT "index", text FROM text_data WHERE category=142')
        for idx, text in cursor.fetchall():
            cond[idx] = text
        cursor.execute('SELECT "index", text FROM text_data WHERE category=47')
        skill_names = {idx: text for idx, text in cursor.fetchall()}
        cursor.execute('SELECT id, group_id FROM skill_data')
        group_to_names = {}
        for sid, group_id in cursor.fetchall():
            name = skill_names.get(sid)
            if name:
                group_to_names.setdefault(group_id, []).append(name)
        for group_id, names in group_to_names.items():
            chosen = None
            for n in names:
                if '○' in n:
                    chosen = n
                    break
            if not chosen:
                for n in names:
                    if '◎' not in n and '×' not in n:
                        chosen = n
                        break
            if not chosen:
                chosen = names[0]
            skill[group_id] = chosen
        conn.close()
    except:
        pass
    return story, cond, skill

mdb_cache, condition_cache, skill_cache = build_mdb_caches()

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

def get_energy_outcome(diff):
    if not diff:
        return ""
    parts = []
    if "vital" in diff:
        v = diff["vital"]
        sign = "+" if v > 0 else ""
        parts.append(f"Vital {sign}{v}")
    if "max_vital" in diff:
        v = diff["max_vital"]
        sign = "+" if v > 0 else ""
        parts.append(f"Max Vital {sign}{v}")
    return ", ".join(parts)

def get_stats_outcome(diff):
    if not diff:
        return ""
    parts = []
    mapping = {
        "speed": "Speed",
        "stamina": "Stamina",
        "power": "Power",
        "guts": "Guts",
        "wiz": "Wit",
        "motivation": "Mood",
        "skill_point": "SP"
    }
    for k, name in mapping.items():
        if k in diff:
            v = diff[k]
            sign = "+" if v > 0 else ""
            parts.append(f"{name} {sign}{v}")
    return ", ".join(parts)

def get_hints_outcome(diff):
    if not diff or "gained_skill_hints" not in diff:
        return ""
    hints = diff["gained_skill_hints"]
    parts = []
    for hid, lvl in hints.items():
        try:
            val_int = int(hid)
            name = skill_cache.get(val_int, hid)
        except:
            name = hid
        parts.append(f"{name} ({lvl})")
    return ", ".join(parts)

def get_conditions_outcome(diff):
    if not diff:
        return ""
    parts = []
    if "gained_conditions" in diff:
        for cid in diff["gained_conditions"]:
            name = condition_cache.get(cid, str(cid))
            parts.append(f"Gain [{name}]")
    if "lost_conditions" in diff:
        for cid in diff["lost_conditions"]:
            name = condition_cache.get(cid, str(cid))
            parts.append(f"Lose [{name}]")
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
    global current_event_state, outcomes_db, current_facilities_state
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
                    turn = chara_info_current.get("turn", 0)
                    broadcast({"status": "energy_update", "vital": chara_info_current["vital"], "max_vital": chara_info_current["max_vital"], "turn": turn})
                
                if chara_info_current and all(k in chara_info_current for k in ["speed", "stamina", "power", "guts", "wiz"]):
                    broadcast({
                        "status": "stats_update",
                        "speed": chara_info_current["speed"],
                        "max_speed": chara_info_current.get("max_speed", 1200),
                        "stamina": chara_info_current["stamina"],
                        "max_stamina": chara_info_current.get("max_stamina", 1200),
                        "power": chara_info_current["power"],
                        "max_power": chara_info_current.get("max_power", 1200),
                        "guts": chara_info_current["guts"],
                        "max_guts": chara_info_current.get("max_guts", 1200),
                        "wiz": chara_info_current["wiz"],
                        "max_wiz": chara_info_current.get("max_wiz", 1200)
                    })

                command_arr = []
                if "home_info" in data_block and isinstance(data_block["home_info"], dict):
                    command_arr.extend(data_block["home_info"].get("command_info_array", []))
                if "free_data_set" in data_block and isinstance(data_block["free_data_set"], dict):
                    command_arr.extend(data_block["free_data_set"].get("command_info_array", []))
                if "command_info_array" in data_block and isinstance(data_block["command_info_array"], list):
                    command_arr.extend(data_block["command_info_array"])
                
                has_fac_updates = False
                for cmd in command_arr:
                    if not isinstance(cmd, dict):
                        continue
                    cmd_id = cmd.get("command_id")
                    if cmd_id in CMD_MAPPING:
                        inc_dec = cmd.get("params_inc_dec_info_array", [])
                        if inc_dec:
                            stat_name, primary_target = CMD_MAPPING[cmd_id]
                            stat_val = 0
                            sp_val = 0
                            energy_val = 0
                            for item in inc_dec:
                                if not isinstance(item, dict):
                                    continue
                                t_type = item.get("target_type")
                                val = item.get("value", 0)
                                if t_type in (1, 2, 3, 4, 5):
                                    stat_val += val
                                elif t_type == 30:
                                    sp_val += val
                                elif t_type == 10:
                                    energy_val += val
                            current_facilities_state[stat_name] = {"stat": stat_val, "sp": sp_val, "energy": energy_val}
                            has_fac_updates = True
                if has_fac_updates:
                    broadcast({"status": "facilities_update", "facilities": current_facilities_state})

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
                                display_choices.append({"slot": ui_slot + 1, "index": select_index, "status": "mapped", "diff": outcome_diff})
                            else:
                                display_choices.append({"slot": ui_slot + 1, "index": select_index, "status": "unmapped", "diff": None})
                        
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
        self.overrideredirect(True)
        self.geometry("850x450")
        self.configure(bg="#000000")
        
        try:
            import ctypes
            hwnd = self.winfo_id()
            parent = ctypes.windll.user32.GetParent(hwnd)
            if parent:
                style = ctypes.windll.user32.GetWindowLongW(parent, -20)
                style = style & ~0x00000080
                style = style | 0x00040000
                ctypes.windll.user32.SetWindowLongW(parent, -20, style)
                ctypes.windll.user32.SetWindowPos(parent, 0, 0, 0, 0, 0, 0x0027)
        except:
            pass
            
        self.aot = True
        self.attributes('-topmost', True)
        self.drag_x = 0
        self.drag_y = 0
        
        self.title_bar = tk.Frame(self, bg="#1a1a1a", height=28)
        self.title_bar.pack(fill="x", side="top")
        self.title_bar.pack_propagate(False)
        
        title_lbl = tk.Label(self.title_bar, text=" Lil dumpy", fg="#aaaaaa", bg="#1a1a1a", font=("Consolas", 9, "bold"))
        title_lbl.pack(side="left", padx=5)
        
        btn_close = tk.Button(self.title_bar, text="✕", command=self.destroy, bg="#1a1a1a", fg="#aaaaaa", activebackground="#ff5f56", activeforeground="white", bd=0, font=("Consolas", 10), width=3)
        btn_close.pack(side="right")
        
        btn_min = tk.Button(self.title_bar, text="—", command=self.iconify, bg="#1a1a1a", fg="#aaaaaa", activebackground="#333333", activeforeground="white", bd=0, font=("Consolas", 10), width=3)
        btn_min.pack(side="right")
        
        def on_enter_close(e):
            btn_close.configure(bg="#ff5f56", fg="white")
        def on_leave_close(e):
            btn_close.configure(bg="#1a1a1a", fg="#aaaaaa")
        btn_close.bind("<Enter>", on_enter_close)
        btn_close.bind("<Leave>", on_leave_close)

        def on_enter_min(e):
            btn_min.configure(bg="#333333", fg="white")
        def on_leave_min(e):
            btn_min.configure(bg="#1a1a1a", fg="#aaaaaa")
        btn_min.bind("<Enter>", on_enter_min)
        btn_min.bind("<Leave>", on_leave_min)
        
        def start_move(event):
            self.drag_x = event.x
            self.drag_y = event.y
        def do_move(event):
            x = self.winfo_x() + (event.x - self.drag_x)
            y = self.winfo_y() + (event.y - self.drag_y)
            self.geometry(f"+{x}+{y}")
            
        self.title_bar.bind("<Button-1>", start_move)
        self.title_bar.bind("<B1-Motion>", do_move)
        title_lbl.bind("<Button-1>", start_move)
        title_lbl.bind("<B1-Motion>", do_move)
        
        self.header_frame = tk.Frame(self, bg="#000000")
        self.header_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        self.left_frame = tk.Frame(self.header_frame, bg="#000000")
        self.left_frame.pack(side="left", anchor="w")
        
        self.warn_lbl = tk.Label(self.left_frame, text="Order not guaranteed infer order from results", fg="#ff9800", bg="#000000", font=("Consolas", 8))
        self.warn_lbl.pack(anchor="w", padx=0, pady=0)
        
        self.energy_var = tk.StringVar()
        self.energy_var.set("Energy: ?/?")
        self.energy_lbl = tk.Label(self.left_frame, textvariable=self.energy_var, fg="#4caf50", bg="#000000", font=("Consolas", 10, "bold"))
        self.energy_lbl.pack(anchor="w", padx=0, pady=0)
        
        self.info_lbl = tk.Label(self.left_frame, text="Turn: ? | Next Summer: ?", fg="white", bg="#000000", font=("Consolas", 10))
        self.info_lbl.pack(anchor="w", padx=0, pady=0)
        
        self.btn_aot = tk.Button(self.header_frame, text="ALWAYS ON TOP: ON", command=self.toggle_aot, bg="#222222", fg="white", font=("Consolas", 9), relief="solid", bd=1)
        self.btn_aot.pack(side="right", anchor="e", padx=0, pady=0)
        
        self.event_lbl = tk.Label(self, text="WAITING FOR EVENT...", fg="white", bg="#000000", font=("Consolas", 10, "bold"))
        self.event_lbl.pack(anchor="w", padx=10, pady=(5, 5))
        
        self.choices_frame = tk.Frame(self, bg="#000000")
        self.choices_frame.pack(fill="both", expand=True, padx=10, pady=(5, 5))
        self.choices_frame.grid_rowconfigure(0, weight=1)
        
        self.fac_frame = tk.Frame(self, bg="#000000")
        self.fac_frame.pack(fill="x", padx=10, pady=(5, 10))
        for i in range(5):
            self.fac_frame.columnconfigure(i, weight=1)
            
        stats_info = [
            ("Speed", "speed", "max_speed", "#ff7675"),
            ("Stamina", "stamina", "max_stamina", "#74b9ff"),
            ("Power", "power", "max_power", "#ffeaa7"),
            ("Guts", "guts", "max_guts", "#a29bfe"),
            ("Wit", "wiz", "max_wiz", "#55efc4")
        ]
        
        self.fac_widgets = {}
        for idx, (display_name, key, max_key, color) in enumerate(stats_info):
            col_frame = tk.Frame(self.fac_frame, bg="#111111", highlightbackground="#333333", highlightthickness=1, bd=0)
            col_frame.grid(row=0, column=idx, padx=5, pady=2, sticky="nsew")
            
            hdr_lbl = tk.Label(col_frame, text=f"{display_name}: ? to cap", fg=color, bg="#111111", font=("Consolas", 9, "bold"))
            hdr_lbl.pack(anchor="w", padx=5, pady=(2, 0))
            
            stat_lbl = tk.Label(col_frame, text="Stat: +0", fg="white", bg="#111111", font=("Consolas", 9))
            stat_lbl.pack(anchor="w", padx=5, pady=0)
            
            sp_lbl = tk.Label(col_frame, text="SP: +0", fg="white", bg="#111111", font=("Consolas", 9))
            sp_lbl.pack(anchor="w", padx=5, pady=0)
            
            energy_lbl = tk.Label(col_frame, text="Energy: +0", fg="white", bg="#111111", font=("Consolas", 9))
            energy_lbl.pack(anchor="w", padx=5, pady=(0, 2))
            
            self.fac_widgets[key] = {
                "hdr": hdr_lbl,
                "stat": stat_lbl,
                "sp": sp_lbl,
                "energy": energy_lbl,
                "display_name": display_name,
                "max_key": max_key
            }
            
        self.choice_cards = []
        for i in range(6):
            card_frame = tk.Frame(self.choices_frame, bg="#111111", highlightbackground="#333333", highlightthickness=1, bd=0)
            
            header_lbl = tk.Label(card_frame, text=f"Choice {i+1}", fg="#ffffff", bg="#222222", font=("Consolas", 9, "bold"), anchor="center")
            header_lbl.pack(fill="x", side="top")
            
            energy_lbl = tk.Label(card_frame, text="", fg="#55efc4", bg="#111111", font=("Consolas", 8), justify="left", anchor="w", wraplength=180)
            energy_lbl.pack(fill="x", padx=5, pady=2)
            
            stats_lbl = tk.Label(card_frame, text="", fg="#ffeaa7", bg="#111111", font=("Consolas", 8), justify="left", anchor="w", wraplength=180)
            stats_lbl.pack(fill="x", padx=5, pady=2)
            
            hints_lbl = tk.Label(card_frame, text="", fg="#ff7675", bg="#111111", font=("Consolas", 8), justify="left", anchor="w", wraplength=180)
            hints_lbl.pack(fill="x", padx=5, pady=2)
            
            conds_lbl = tk.Label(card_frame, text="", fg="#ffffff", bg="#111111", font=("Consolas", 8), justify="left", anchor="w", wraplength=180)
            conds_lbl.pack(fill="x", padx=5, pady=2)
            
            self.choice_cards.append({
                "frame": card_frame,
                "header": header_lbl,
                "energy": energy_lbl,
                "stats": stats_lbl,
                "hints": hints_lbl,
                "conds": conds_lbl
            })
            
        self.after(100, self.poll_queue)

    def toggle_aot(self):
        self.aot = not self.aot
        self.attributes('-topmost', self.aot)
        self.btn_aot.configure(text=f"ALWAYS ON TOP: {'ON' if self.aot else 'OFF'}")

    def format_turn_info(self, turn):
        if turn < 37:
            camp = f"{37 - turn}t"
        elif 37 <= turn <= 40:
            camp = "Active!"
        elif turn < 61:
            camp = f"{61 - turn}t"
        elif 61 <= turn <= 64:
            camp = "Active!"
        else:
            camp = "None"
        
        return f"Turn: {turn} | Next Summer: {camp}"

    def poll_queue(self):
        while not ui_queue.empty():
            msg = ui_queue.get()
            if msg["status"] == "energy_update":
                self.energy_var.set(f"Energy: {msg['vital']}/{msg['max_vital']}")
                turn = msg.get("turn", 0)
                self.info_lbl.configure(text=self.format_turn_info(turn))
            elif msg["status"] == "stats_update":
                for key, widget in self.fac_widgets.items():
                    current_val = msg.get(key, 0)
                    max_key = widget["max_key"]
                    max_cap = msg.get(max_key, 1200)
                    rem = max(0, max_cap - current_val)
                    widget["hdr"].configure(text=f"{widget['display_name']}: {rem} to cap")
            elif msg["status"] == "facilities_update":
                fac = msg.get("facilities", {})
                for key, widget in self.fac_widgets.items():
                    fac_key = "wit" if key == "wiz" else key
                    data = fac.get(fac_key, {"stat": 0, "sp": 0, "energy": 0})
                    widget["stat"].configure(text=f"Stat: {data['stat']:+}")
                    widget["sp"].configure(text=f"SP: {data['sp']:+}")
                    widget["energy"].configure(text=f"Energy: {data['energy']:+}")
            elif msg["status"] == "waiting":
                self.event_lbl.configure(text="[WAITING...]")
                for card in self.choice_cards:
                    card["frame"].grid_forget()
                self.geometry("850x450")
            elif msg["status"] == "event":
                self.event_lbl.configure(text=f"Event: {msg['event_name']}")
                for card in self.choice_cards:
                    card["frame"].grid_forget()
                choices = msg.get("choices", [])
                num_choices = len(choices)
                for i in range(6):
                    if i < num_choices:
                        self.choices_frame.columnconfigure(i, weight=1)
                    else:
                        self.choices_frame.columnconfigure(i, weight=0)
                width = max(850, num_choices * 180 + 30)
                self.geometry(f"{width}x450")
                for c in choices:
                    slot = c["slot"]
                    idx = c["index"]
                    card_idx = slot - 1
                    if 0 <= card_idx < len(self.choice_cards):
                        card = self.choice_cards[card_idx]
                        card["frame"].grid(row=0, column=card_idx, padx=5, pady=5, sticky="nsew")
                        card["header"].configure(text=f"Choice {slot} (Idx {idx})")
                        if c["status"] == "mapped" and c.get("diff") is not None:
                            diff = c["diff"]
                            e_out = get_energy_outcome(diff)
                            s_out = get_stats_outcome(diff)
                            h_out = get_hints_outcome(diff)
                            c_out = get_conditions_outcome(diff)
                            card["energy"].configure(text=e_out if e_out else "")
                            card["stats"].configure(text=s_out if s_out else "")
                            card["hints"].configure(text=h_out if h_out else "")
                            card["conds"].configure(text=c_out if c_out else "")
                        else:
                            card["energy"].configure(text="Not mapped")
                            card["stats"].configure(text="")
                            card["hints"].configure(text="")
                            card["conds"].configure(text="")
        self.after(100, self.poll_queue)

if __name__ == "__main__":
    app = Dumpy()
    threading.Thread(target=start_frida, args=(app,), daemon=True).start()
    app.mainloop()