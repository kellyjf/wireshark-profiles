-- skew.lua
-- A post-dissector to compute the difference between system and RTP time
-- for RTP streams separately by SSRC
--
-- Author: John Kelly
-- Date:   2/26/2014
--

-- Helper function for debugging
function print_table(x)
	for k,v in pairs(x) do
		print(k,v)
	end
end

do
	-- Create the 'new protocol' dissector
        local sysng = Proto("sysng", "SysLog Data");
	local deja;

	--print_table(sysng)

	-- Create the new fields, and associate to the protocol
        local F_pid = ProtoField.string("sysng.pid", "PID")
        local F_unit = ProtoField.string("sysng.unit", "Unit")
        local F_pri = ProtoField.string("sysng.priority", "Priority")
        local F_sid = ProtoField.string("sysng.ident", "Ident")
        local F_bsrc = ProtoField.string("sysng.bsrc", "Code File")
        local F_bline = ProtoField.string("sysng.bline", "Code Line")
        local F_body = ProtoField.string("sysng.line", "Log Message")
        sysng.fields = {F_pri, F_unit, F_sid, F_pid, F_bsrc, F_bline, F_body}

	-- Create acccessors for the fields we need to reference
        local f_ethtype = Field.new("eth.type")
	--print_table(f_ethtype);

	-- Define the dissector function
        function sysng.dissector(tvbuffer, pinfo, treeitem)

		-- Store the top of the analysis tree
		local subtreeitem = treeitem:add(sysng, tvbuffer)

		--print(ssrc_val,f_frame_time(),f_rtp_time(),skew_val,start_offset[ssrc_val],(skew_val - start_offset[ssrc_val]))

		--print("String",linelen,(tvbuffer(8,linelen):string()))


		-- Add the values to the analysis tree
		--subtreeitem:add(tvbuffer(0,2), "Source")
		--	   :set_text("Source: " .. tvbuffer(0,2))
		--if ( deja~=1 ) then print_table(pinfo.cols); deja=1; end
		local ndx=0
		local slen=0
		--
		-- PID
		subtreeitem:add(F_pid, tvbuffer(ndx,2), (tvbuffer(ndx,2):le_uint()))
			   :set_text("PID: " .. tvbuffer(ndx,2):le_uint())
		ndx=ndx+2 

		-- Pri
		subtreeitem:add(F_pri, tvbuffer(ndx,2), (tvbuffer(ndx,2):le_uint()))
			   :set_text("Priority: " .. tvbuffer(ndx,2):le_uint())
		ndx=ndx+2 

		-- Systemd Unit
		slen = tvbuffer(ndx,2):le_uint();
		ndx=ndx+2 
		--print("Unit",ndx,slen)
		subtreeitem:add(F_unit, tvbuffer(ndx,slen), (tvbuffer(ndx,slen):string()))
			   :set_text("Unit: " .. tvbuffer(ndx,slen):string())
		ndx=ndx+slen 

		-- Syslog ID
		slen = tvbuffer(ndx,2):le_uint();
		ndx=ndx+2 
		--print("Ident",ndx,slen)
		subtreeitem:add(F_sid, tvbuffer(ndx,slen), (tvbuffer(ndx,slen):string()))
			   :set_text("Ident: " .. tvbuffer(ndx,slen):string())
		ndx=ndx+slen 

		-- Code file
		slen = tvbuffer(ndx,2):le_uint();
		ndx=ndx+2 
		--print("File",ndx,slen)
		subtreeitem:add(F_bsrc, tvbuffer(ndx,slen), (tvbuffer(ndx,slen):string()))
			   :set_text("File: " .. tvbuffer(ndx,slen):string())
		pinfo.cols.net_src =  tvbuffer(ndx,slen):string();
		ndx=ndx+slen 
		--
		-- Code Line
		slen = tvbuffer(ndx,2):le_uint();
		ndx=ndx+2 
		--print("Line",ndx,slen)
		subtreeitem:add(F_bline, tvbuffer(ndx,slen), (tvbuffer(ndx,slen):string()))
			   :set_text("Line: " .. tvbuffer(ndx,slen):string())
		ndx=ndx+slen 

		-- Message
		slen = tvbuffer(ndx,2):le_uint();
		ndx=ndx+2 
		--print("Msg",ndx,slen)
		subtreeitem:add(F_body, tvbuffer(ndx,slen), (tvbuffer(ndx,slen):string()))
			   :set_text("Mesasge: " .. tvbuffer(ndx,slen):string())

		pinfo.cols.protocol = "sysng"
		pinfo.cols.net_dst = "SysLog"
		pinfo.cols.info = tvbuffer(ndx,slen):string() 

        end
	local dt = DissectorTable.get("ethertype");
	dt:add(0x7dff, sysng);
--	register_postdissector(sysng)
end
