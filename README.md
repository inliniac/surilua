Lua Suricata
============

Lua scripts for use with Suricata


<h2> stats.lua -- a performance analysis script</h2>

Enable the 'lua' output module in your YAML and add the script there. It's read from the current work dir unless you use a absolute path.

<pre>
outputs:
  - lua:
      enabled: yes
      scripts:
        - stats.lua
</pre>

Requires Suricata git master or 2.1beta3+, with Lua support enabled.
