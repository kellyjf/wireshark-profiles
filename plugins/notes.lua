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
        local note = Proto("note", "Log Data");
	local deja;

	--print_table(notes)

	-- Create the new fields, and associate to the protocol
        local F_source = ProtoField.string("note.src", "Source")
        local F_thread = ProtoField.string("note.thread", "Thread")
        local F_len = ProtoField.string("note.len", "Length")
        local F_body = ProtoField.stringz("note.line", "Log Message")
        note.fields = {F_source, F_thread, F_len, F_body}

	-- Create acccessors for the fields we need to reference
        local f_ethtype = Field.new("eth.type")
	--print_table(f_ethtype);

	-- Define the dissector function
        function note.dissector(tvbuffer, pinfo, treeitem)

		-- Store the top of the analysis tree
		local subtreeitem = treeitem:add(note, tvbuffer)
		local linelen = tvbuffer(6,2):le_uint();

		--print(ssrc_val,f_frame_time(),f_rtp_time(),skew_val,start_offset[ssrc_val],(skew_val - start_offset[ssrc_val]))

		--print("String",linelen,(tvbuffer(8,linelen):string()))


		-- Add the values to the analysis tree
		--subtreeitem:add(tvbuffer(0,2), "Source")
		--	   :set_text("Source: " .. tvbuffer(0,2))
		--if ( deja~=1 ) then print_table(pinfo.cols); deja=1; end
		pinfo.cols.protocol = "logs"
		pinfo.cols.net_src = "FG Logs"
		pinfo.cols.net_dst = "FG Logs"
		pinfo.cols.info = tvbuffer(8,linelen):string() 

		subtreeitem:add(F_source, tvbuffer(0,2), (tvbuffer(0,2):string()))
			   :set_text("Source: " .. tvbuffer(0,2):string())
		subtreeitem:add(F_thread, tvbuffer(2,4), (tvbuffer(2,4):string()))
			   :set_text("Thread: " .. tvbuffer(2,4):string())
		subtreeitem:add(F_len, tvbuffer(6,2), (tvbuffer(6,2):le_uint()))
			   :set_text("Length: " .. tvbuffer(6,2):le_uint())
		subtreeitem:add(F_body, tvbuffer(8,linelen), (tvbuffer(8,linelen):string()))
			   :set_text("Body: " .. tvbuffer(8,linelen):string())

        end
	local dt = DissectorTable.get("ethertype");
	dt:add(0x7fff, note);
--	register_postdissector(notes)
end
