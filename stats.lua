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

function log(args)
    t = { capture_drops = 0 }
    p = { capture_drops = 0 }

    for n, v in ipairs(args) do
        store_values(t,v)
        store_pvalues(p,v)
    end

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
