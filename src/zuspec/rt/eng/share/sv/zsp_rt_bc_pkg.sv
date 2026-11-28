// zsp_rt_bc_pkg, C engine variant: the bytecode runtime over the native
// engine (this package's C library, `libpssvm`) through DPI-C; no Python
// in the simulator. Hand-written, shipped with zuspec-rt-eng (`share/sv`,
// `zuspec.rt.eng.sv_dir()`), next to the library it binds. The pyvm
// variant (zuspec-be-bc share/sv/zsp_rt_bc_pkg.sv) has the same package
// and class names: the file a build compiles chooses the interpreter
// (design pssvm-in-practice.md §2.1).
//
// Compile with zuspec-be-bc's share/sv on +incdir (zsp_rt_bc_common.svh,
// the method list's generated files) and link the engine library
// (`pssc sv-pssvm-path --lib`).
//
//   zsp_rt_bc eng = zsp_rt_bc::load("x.zbc", "seed=3");
//
// Load options (`opts`, comma-separated) are the C engine's: root=<type>,
// seed=<n>, seed_mode=keyed|stream, trace=<file>, trace_mask=<n>,
// verbosity=<n>, step_limit=<n>; and dbg_signal=1, dbg_start=1, served in
// SV. Any other option (pyvm's platform=, ...) is ignored and reported.
// The package reads no plusargs: its host passes every option.
//
// `class zsp_rt_bc` overrides what the C engine serves. Every other method
// of the list (zuspec-be-bc rt_bc_api.py) is zsp_rt_bc_base's: a refusal
// through error(0). The C engine is on hold (pssc pssvm-plan): it has no
// object handles, link check, step/pending, progress count or self-wait
// detection, and its C ABI keeps the `pssvm_*` names for now.

package zsp_rt_bc_pkg;

`include "zsp_rt_bc_common.svh"

  // The native engine's DPI-C entry points: the host ABI with handles as
  // chandles and the request read field by field (a thin C adapter over
  // pssvm.h).
  import "DPI-C" context function int     pssvm_abi_version();
  import "DPI-C" context function chandle pssvm_dpi_load(string path, string opts);
  import "DPI-C" context function int     pssvm_dpi_construct(chandle e, string root_type);
  // Arguments are staged one by one (no open array: Verilator 5.052 cannot
  // compile one in an import).
  import "DPI-C" context function void    pssvm_dpi_arg_push(chandle e, longint unsigned v);
  import "DPI-C" context function chandle pssvm_dpi_call_start(chandle e, string entry,
                                                               string comp_path);
  import "DPI-C" context function int     pssvm_run(chandle h);
  import "DPI-C" context function int     pssvm_dpi_take(chandle h);
  import "DPI-C" context function int     pssvm_dpi_req_int(chandle h, int rid, string field);
  import "DPI-C" context function longint unsigned pssvm_dpi_req_u64(chandle h, int rid, string field);
  import "DPI-C" context function string  pssvm_dpi_req_str(chandle h, int rid, string field);
  import "DPI-C" context function int     pssvm_dpi_req_nargs(chandle h, int rid);
  import "DPI-C" context function longint unsigned pssvm_dpi_req_arg(chandle h, int rid, int i);
  import "DPI-C" context function int     pssvm_dpi_complete(chandle h, int rid, longint unsigned data);
  import "DPI-C" context function int     pssvm_dpi_set_ret(chandle h, int rid, int i,
                                                            longint unsigned v);
  import "DPI-C" context function longint unsigned pssvm_dpi_result(chandle h);
  import "DPI-C" context function void    pssvm_call_end(chandle h);
  import "DPI-C" context function longint unsigned pssvm_dpi_obj_field(chandle h, string name);
  import "DPI-C" context function int     pssvm_notify(chandle e, int kind, int id,
                                                       longint unsigned value);
  import "DPI-C" context function string  pssvm_dpi_error(chandle e, chandle h);
  import "DPI-C" context function void    pssvm_free(chandle e);
  import "DPI-C" context function string  pssvm_dpi_test_name(chandle e, int i);
  import "DPI-C" context function string  pssvm_dpi_test_expect(chandle e, int i);
  import "DPI-C" context function int     pssvm_dpi_exec_id(chandle e, string path);
  import "DPI-C" context function int     pssvm_dpi_event_id(chandle e, string path);
  import "DPI-C" context function int     pssvm_dpi_time_exp(chandle e);
  import "DPI-C" context function string  pssvm_dpi_exec_path(chandle e, int id);
  import "DPI-C" context function string  pssvm_dpi_string(chandle e, int idx);
  import "DPI-C" context function string  pssvm_dpi_hook(chandle e, string kind, int i);
  import "DPI-C" context function int     pssvm_dpi_checks_failed(chandle e);
  import "DPI-C" context function string  pssvm_dpi_msg_next(chandle e);
  import "DPI-C" context function int     pssvm_dpi_msg_sev(chandle e);
  // pssvm_run, with a debugger's stops (server mode, `debug`) served in C.
  import "DPI-C" context function int     pssvm_dpi_run(chandle h);
  // Server mode (the workspace daemon's sim socket), in C.
  import "DPI-C" context function string  pssvm_dpi_serve(chandle e, string name, string top);
  import "DPI-C" context function int     pssvm_dpi_poll(chandle e, int timeout_ms);
  import "DPI-C" context function string  pssvm_dpi_pending_sel(chandle e);
  import "DPI-C" context function void    pssvm_dpi_serve_test(chandle e, string name,
                                                               int passed);
  import "DPI-C" context function void    pssvm_dpi_serve_done(chandle e, int n_pass,
                                                               int n_fail);
  import "DPI-C" context function void    pssvm_dpi_set_time(chandle e, longint unsigned t_fs);
  import "DPI-C" context function int     pssvm_dpi_dbg_wait(chandle e, string why);

  class zsp_rt_bc extends zsp_rt_bc_base;
    chandle e;
    chandle calls[int];
    int     next_id = 1;
    string  root_type;

    // Load image `img` and construct its tree (opts `root=<type>`; "" =
    // the image's); null (and why, on stdout) on failure.
    static function zsp_rt_bc load(string img, string opts = "");
      string known[$] = '{"root", "seed", "seed_mode", "trace", "trace_mask",
                          "verbosity", "step_limit"};
      zsp_rt_bc eng = new();
      bit dbg_start;
      zsp_rt_bc_sv_opts(opts, dbg_start);
      zsp_rt_bc_check_opts("the C engine", opts, known);
      eng.root_type = opt_value(opts, "root");
      eng.e = pssvm_dpi_load(img, opts);
      if (eng.e != null && pssvm_dpi_construct(eng.e, eng.root_type) != 0) begin
        $display("PSSVM-ERROR: load %s: %s", img, pssvm_dpi_error(eng.e, null));
        return null;
      end
      if (eng.e == null) begin
        $display("PSSVM-ERROR: load %s: %s", img, pssvm_dpi_error(null, null));
        return null;
      end
      zsp_rt_bc_loaded(eng, dbg_start);
      return eng;
    endfunction

    // The root component type image `img` loads by default, read without
    // loading it: "" here, as the C engine has no such query yet (a host
    // names the engine itself).
    static function string image_root(string img);
      return "";
    endfunction

    // The value of option `key` in `opts` ("" when absent).
    protected static function string opt_value(string opts, string key);
      string pre = {key, "="};
      int b = 0;
      for (int i = 0; i <= opts.len(); i++)
        if (i == opts.len() || opts[i] == ",") begin
          if (i - b > pre.len() && opts.substr(b, b + pre.len() - 1) == pre)
            return opts.substr(b + pre.len(), i - 1);
          b = i + 1;
        end
      return "";
    endfunction

    virtual function string impl();
      return "the C engine (zuspec-rt-eng)";
    endfunction

    virtual function int fresh();
      return (e != null) ? pssvm_dpi_construct(e, root_type) : -1;
    endfunction

    virtual function int call_start(string entry, string comp_path,
                                    longint unsigned args[$]);
      chandle h;
      if (e == null) return 0;
      foreach (args[i]) pssvm_dpi_arg_push(e, args[i]);
      h = pssvm_dpi_call_start(e, entry, comp_path);
      if (h == null) return 0;
      calls[next_id] = h;
      return next_id++;
    endfunction

    virtual function zsp_rt_bc_status_e run(int h);
      return zsp_rt_bc_status_e'(pssvm_dpi_run(calls[h]));
    endfunction

    virtual function int take(int h);
      return pssvm_dpi_take(calls[h]);
    endfunction

    virtual function void request(int h, int rid, zsp_rt_bc_req req);
      chandle c = calls[h];
      int n;
      req.req_id   = rid;
      req.api      = pssvm_dpi_req_int(c, rid, "api");
      req.executor = pssvm_dpi_req_int(c, rid, "executor");
      req.thread   = pssvm_dpi_req_int(c, rid, "thread");
      req.write    = pssvm_dpi_req_int(c, rid, "kind") != 0;
      req.addr     = pssvm_dpi_req_u64(c, rid, "addr");
      req.size     = pssvm_dpi_req_int(c, rid, "size");
      req.data     = pssvm_dpi_req_u64(c, rid, "data");
      req.reg_id   = pssvm_dpi_req_int(c, rid, "reg_id");
      req.src_ref  = pssvm_dpi_req_str(c, rid, "src_ref");
      req.fn_id    = pssvm_dpi_req_int(c, rid, "fn_id");
      req.name     = pssvm_dpi_req_str(c, rid, "name");
      req.blocking = pssvm_dpi_req_int(c, rid, "blocking") != 0;
      req.on       = zsp_rt_bc_wait_on_e'(pssvm_dpi_req_int(c, rid, "on"));
      req.delay    = pssvm_dpi_req_u64(c, rid, "delay");
      req.reason   = pssvm_dpi_req_str(c, rid, "reason");
      req.args.delete();
      n = pssvm_dpi_req_nargs(c, rid);
      for (int i = 0; i < n; i++) req.args.push_back(pssvm_dpi_req_arg(c, rid, i));
      req.nret     = pssvm_dpi_req_int(c, rid, "nret");
      req.rets.delete();
      req.ret_s.delete();
    endfunction

    virtual function int complete(int h, int rid, longint unsigned data);
      return pssvm_dpi_complete(calls[h], rid, data);
    endfunction

    virtual function int set_ret(int h, int rid, int i, longint unsigned v);
      return pssvm_dpi_set_ret(calls[h], rid, i, v);
    endfunction

    virtual function longint unsigned result(int h);
      return pssvm_dpi_result(calls[h]);
    endfunction

    virtual function longint unsigned obj_field(int h, string name);
      return pssvm_dpi_obj_field(calls[h], name);
    endfunction

    virtual function void call_end(int h);
      if (!calls.exists(h)) return;
      pssvm_call_end(calls[h]);
      calls.delete(h);
    endfunction

    virtual function int notify(int kind, int id, longint unsigned value);
      return pssvm_notify(e, kind, id, value);
    endfunction

    virtual function string error(int h);
      chandle c = null;
      if (h == 0 && refusal != "") return take_refusal();
      if (calls.exists(h)) c = calls[h];
      return pssvm_dpi_error(e, c);
    endfunction

    // The image's test list (its "pssc.native" document) and the pssunit
    // ledgers' failure counts in the component tree.
    virtual function string test_name(int i);
      return (e != null) ? pssvm_dpi_test_name(e, i) : "";
    endfunction

    virtual function int exec_id(string path);
      return (e != null) ? pssvm_dpi_exec_id(e, path) : -1;
    endfunction

    virtual function int event_id(string path);
      return (e != null) ? pssvm_dpi_event_id(e, path) : -1;
    endfunction

    virtual function int time_exp();
      return (e != null) ? pssvm_dpi_time_exp(e) : -12;
    endfunction

    virtual function string exec_path(int id);
      return (e != null) ? pssvm_dpi_exec_path(e, id) : "";
    endfunction

    virtual function string string_at(int idx);
      return (e != null) ? pssvm_dpi_string(e, idx) : "";
    endfunction

    virtual function string message_next(output int sev);
      string m = (e != null) ? pssvm_dpi_msg_next(e) : "";
      sev = (m != "") ? pssvm_dpi_msg_sev(e) : 0;
      return m;
    endfunction

    virtual function string test_expect(int i);
      return (e != null) ? pssvm_dpi_test_expect(e, i) : "";
    endfunction

    virtual function string hook(string kind, int i);
      return (e != null) ? pssvm_dpi_hook(e, kind, i) : "";
    endfunction

    virtual function int checks_failed();
      return (e != null) ? pssvm_dpi_checks_failed(e) : 0;
    endfunction

    // The C engine keeps no bench reports: an error or fatal is counted
    // here, so it still fails the test running (not attributed, F7.6a).
    int n_bench_failed;
    virtual function int report(string kind, longint unsigned t_fs,
                                string json);
      if (zsp_rt_bc_str_has(json, "\"severity\":\"error\"") ||
          zsp_rt_bc_str_has(json, "\"severity\":\"fatal\""))
        n_bench_failed++;
      return 0;
    endfunction
    virtual function int bench_failed();
      return n_bench_failed;
    endfunction

    // Server mode, in C (no Python): the channel, a `run`'s tests, holding
    // for a debugger and the debug stub (`debug` {on}).
    virtual function string serve(string name, string top);
      return (e != null) ? pssvm_dpi_serve(e, name, top) : "";
    endfunction

    virtual function int poll(int timeout_ms);
      return pssvm_dpi_poll(e, timeout_ms);
    endfunction

    virtual function string pending_sel();
      return pssvm_dpi_pending_sel(e);
    endfunction

    virtual function void serve_test(string name, int passed);
      pssvm_dpi_serve_test(e, name, passed);
    endfunction

    virtual function void serve_done(int n_pass, int n_fail);
      pssvm_dpi_serve_done(e, n_pass, n_fail);
    endfunction

    virtual function int dbg_wait(string why);
      return (e != null) ? pssvm_dpi_dbg_wait(e, why) : -1;
    endfunction

    virtual function void set_time(longint unsigned t_fs);
      pssvm_dpi_set_time(e, t_fs);
    endfunction
  endclass

endpackage
