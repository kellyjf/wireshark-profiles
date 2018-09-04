-- Author: John Kelly
-- Date:   2/26/2014
--

-- Helper function for debugging
function print_table(x)
	for k,v in pairs(x) do
		print(k,v)
	end
end

function walk_json(jsonitem, tvbuffer, jtable)
	local k,v
	for k,v in pairs(jtable) do
		if type(v)~="table" then
			jsonitem:add(F_json,tvbuffer(0,2),(tvbuffer(0,2):string())):set_text(k..":  "..tostring(v))
		else
			local sjitem=jsonitem:add(F_json,tvbuffer(ndx,slen))
			sjitem:set_text(k)
			walk_json(sjitem, tvbuffer, v)
		end
	end
end


do
	-- Create the 'new protocol' dissector
        local amp = Proto("amp", "Aircell Message Protocol");
	local deja;

	json=require('json')
	--print_table(sysng)

	-- Create the new fields, and associate to the protocol
        local F_json = ProtoField.string("amp.json", "json")
        amp.fields = {F_json}

	-- Define the dissector function
        function amp.dissector(tvbuffer, pinfo, treeitem)

		-- Store the top of the analysis tree
		local subtreeitem = treeitem:add(amp, tvbuffer)


		-- Add the values to the analysis tree
		--subtreeitem:add(tvbuffer(0,2), "Source")
		--	   :set_text("Source: " .. tvbuffer(0,2))
		--if ( deja~=1 ) then print_table(pinfo.cols); deja=1; end
		local ndx=0
		local slen=tvbuffer:len()
		--
		-- PID
		local jsonitem =  subtreeitem:add(F_json, tvbuffer(ndx,slen))
		subtreeitem:add(F_json, tvbuffer(ndx,slen), (tvbuffer(ndx,slen):string()))
			   :set_text("JSON: ")

		local jstring=tvbuffer(ndx,slen):string()
		local jtable=json.decode(jstring)
		walk_json(jsonitem, tvbuffer, jtable)
		--print_table(jtable)
		--print_table(jtable['dev'])
	
		pinfo.cols.protocol = "amp"
		pinfo.cols.net_dst = "AMP"
		--pinfo.cols.info = tvbuffer(ndx,slen):string() 
		pinfo.cols.info = jtable['class']
		--pinfo.cols.info =  "AMP Stuff"

        end
	local dt = DissectorTable.get("udp.port");
	dt:add(4000, amp);
--	register_postdissector(amp)
end
