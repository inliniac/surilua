-- simple fast-log to stdout lua module

function init (args)
    local needs = {}
    needs["type"] = "stats"
    return needs
end

function setup (args)
    SCLogInfo("setting up");
end

function store_values (t, v)
    name = string.gsub(v["name"], "%.", "_");
    --print (name)
    if (t[name] ~= nil) then
        t[name] = t[name] + v["value"]
    else
        t[name] = v["value"]
    end
end

function store_pvalues (t, v)
    name = string.gsub(v["name"], "%.", "_");
    --print (name)
    if (t[name] ~= nil) then
        t[name] = t[name] + v["pvalue"]
    else
        t[name] = v["pvalue"]
    end
end

function store_diff (t, v)
    name = string.gsub(v["name"], "%.", "_");
    --print (name)
    local d = v["value"] - v["pvalue"]

    if (t[name] ~= nil) then
        t[name] = t[name] + d;
    else
        t[name] = d;
    end
end

local warnings ={ }

function warn (k, t, v)
    if warnings[k] == nil then
        SCLogWarning("(" .. t .. ") Warning -- " .. v)
        warnings[k] = true
    end

end

function flow_indicators (t, p, d)
    if (t.tcp_no_flow > 0) then
        warn("tcp_no_flow", "flow engine", "TCP packets w/o flow")
    end
    if (t.flow_emerg_mode_entered > 0) then
        warn("flow_emerg_mode_entered", "flow engine", "Emergency mode")
    end
end

function decoder_indicators (t, p, d)
    if (d.decoder_invalid > 0) then
        warn("decoder_invalid", "capture", "getting invalid packets: could be malformed traffic, but also capture problem")
    end
end

function tcp_indicators (t, p, d)
    if (t.tcp_syn > 0 and t.tcp_syn > (t.tcp_synack * 2)) then
        warn("tcp_syn_gt_synack", "capture", "SYN packets greatly outnumber SYN/ACK's: could be a scan/flood, but also a capture problem")
    end
end



function log(args)
    local t = { capture_drops = 0 }
    local p = { capture_drops = 0 }
    local d = { capture_drops = 0 }

    for n, v in ipairs(args) do
        store_values(t,v)
        store_pvalues(p,v)
        store_diff(d,v)
    end
    flow_indicators (t, p, d)
    tcp_indicators (t, p, d)
    decoder_indicators (t, p, d)

    if (t.capture_drops > t.decoder_pkts) then
        print "(perf analyzer) WARNING: massive packet loss detected. Dropping more packets than are processed."
    end

    if (t.capture_drops > 0 and t.capture_drops < (t.decoder_pkts / 100)) then
        print "(perf analyzer) Minor packet loss of less than 1%."
    end

    if (t.tcp_reassembly_gap > (t.tcp_sessions / 10)) then
        print "(perf analyzer) Warning: TCP data gaps detected in more than 10% of the sessions. Possible causes are packet loss (either at the host or SPAN/TAP, NIC offloading."
    end

    if (t.tcp_no_flow > p.tcp_no_flow and t.tcp_no_flow - p.tcp_no_flow > 25) then
        diff = t.tcp_no_flow - p.tcp_no_flow;
        print ("(perf analyzer) Warning: TCP packets w/o associated flow increased by " .. diff .. ". Indication of flow engine in distress.")
    end

    total = t.decoder_pkts + t.capture_drops
    str = string.format("Packets %d (%2.1f%%) processed, dropped %d (%2.1f%%)", t.decoder_pkts, (t.decoder_pkts / total * 100), t.capture_drops, (t.capture_drops / total * 100));
    SCLogInfo(str);

    str = string.format("TCP sessions %d, with gaps %2.1f%%", t.tcp_sessions, ((t.tcp_reassembly_gap * 2) / t.tcp_sessions) * 100)
    SCLogInfo(str);

end

function deinit (args)
end
