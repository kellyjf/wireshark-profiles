-- pds.lua
-- A post-dissector for Ku performance data stream packets
--
-- Author: John Kelly
-- Date:   2/26/2018
--

-- Helper function for debugging
function print_table(x)
	for k,v in pairs(x) do
		print(k,v)
	end
end

do
	-- Create the 'new protocol' dissector
        local pds = Proto("pds", "PDS Data");
        local pdshead = Proto("pdshead", "PDS Header");
        local pdsmsg = Proto("pdsmsg", "PDS Message");
        local pdstail = Proto("pdstail", "PDS Tail");

	-- Create the new fields, and associate to the protocol
        local F_type = ProtoField.uint8("pds.type", "Type")
        local F_version = ProtoField.uint8("pds.version", "Version")
        local F_length = ProtoField.uint16("pds.len", "Length")
        local F_seqno = ProtoField.uint16("pds.seqno", "Sequence")

        local F_rxnoise = ProtoField.int8("pds.rxnoise", "Rx Noise")
        local F_rxlock = ProtoField.uint8("pds.rxlock", "Rx Lock")
        local F_sync = ProtoField.uint8("pds.sync", "Sync")
        local F_l2 = ProtoField.uint8("pds.l2", "L2 Status")
        local F_l3 = ProtoField.uint8("pds.l3", "L3 Status")
        local F_l3 = ProtoField.uint8("pds.l3", "L3 Status")
        local F_mute = ProtoField.uint8("pds.mute", "Mute")
        local F_mutein = ProtoField.uint8("pds.mute", "Mute Input")
        local F_mode = ProtoField.uint8("pds.mode", "Mode")

        local F_rxlevel = ProtoField.int16("pds.rxlevel", "Rx Level")
        local F_txcapa = ProtoField.int32("pds.txcapa", "Tx Cap A")
        local F_txcapb = ProtoField.int32("pds.txcapb", "Tx Cap B")
        local F_txcapc = ProtoField.int32("pds.txcapc", "Tx Cap C")
        local F_tick = ProtoField.uint32("pds.tick", "Rx Tick")
        local F_rxupdatetick = ProtoField.uint32("pds.rxtick", "Tx Tick")
        local F_txupdatetick = ProtoField.uint32("pds.txtick", "Tx Tick")
        local F_txpower = ProtoField.int32("pds.txpower", "Tx Power")

        pdshead.fields = {F_type, F_verson, F_length, F_seqno,
             F_rxnoise, F_rxlock, F_sync, F_l2, F_l3,
	     F_mute, F_mutein, F_mode, F_rxlevel, F_txcapa, F_txcapb,
	     F_txcapc, F_tick, F_updatetick, F_txpower}

	-- Define the dissector function
        function pdshead.dissector(tvbuffer, pinfo, treeitem)
		local subtreeitem = treeitem:add(pdshead, tvbuffer)
		local ndx=0;
		local fsize=1;

		--
		-- Type
		subtreeitem:add(F_type, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Type: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

		-- Version
		subtreeitem:add(F_version, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Version: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

		-- Length Unit
		fsize=2
		subtreeitem:add(F_length, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Length: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

		-- Seqno
		subtreeitem:add(F_seqno, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Sequence: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

	end
        function pdsmsg.dissector(tvbuffer, pinfo, treeitem)
		local subtreeitem = treeitem:add(pdsmsg, tvbuffer)
		local ndx=0;
		local fsize=1;
		fsize=1
		subtreeitem:add(F_rxnoise, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(0)))
			   :set_text("Rx Noise: " .. tvbuffer(ndx,fsize):bitfield(0))
		subtreeitem:add(F_rxlock, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(1)))
			   :set_text("Rx Lock: " .. tvbuffer(ndx,fsize):bitfield(1))
		subtreeitem:add(F_sync, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(2)))
			   :set_text("Sync Status: " .. tvbuffer(ndx,fsize):bitfield(2))
		subtreeitem:add(F_l2, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(3)))
			   :set_text("L2 Status: " .. tvbuffer(ndx,fsize):bitfield(3))
		subtreeitem:add(F_l3, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(4)))
			   :set_text("L3 Status: " .. tvbuffer(ndx,fsize):bitfield(4))
		subtreeitem:add(F_mute, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(5)))
			   :set_text("Mute Open Amip: " .. tvbuffer(ndx,fsize):bitfield(5))
		subtreeitem:add(F_mutein, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(6)))
			   :set_text("Mute Discrete In: " .. tvbuffer(ndx,fsize):bitfield(6))
		subtreeitem:add(F_mode, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):bitfield(7)))
			   :set_text("Operational Mode: " .. tvbuffer(ndx,fsize):bitfield(7))
		ndx=ndx+fsize
		-- Skip reserved byte
		ndx=ndx+1
	end
        function pdstail.dissector(tvbuffer, pinfo, treeitem)
		local subtreeitem = treeitem:add(pdstail, tvbuffer)
		local ndx=0;
		local fsize=1;

		-- Rx Level
		fsize=4
		subtreeitem:add(F_rxlevel, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):int()))
			   :set_text("Rx Level: " .. tvbuffer(ndx,fsize):int())
		ndx=ndx+fsize

		-- Tx Cap A
		fsize=4
		subtreeitem:add(F_txcapa, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):int()))
			   :set_text("TX Cap A: " .. tvbuffer(ndx,fsize):int())
		ndx=ndx+fsize

		-- Tx Cap B
		subtreeitem:add(F_txcapb, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):int()))
			   :set_text("TX Cap B: " .. tvbuffer(ndx,fsize):int())
		ndx=ndx+fsize

		-- Tx Cap C
		subtreeitem:add(F_txcapc, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):int()))
			   :set_text("TX Cap C: " .. tvbuffer(ndx,fsize):int())
		ndx=ndx+fsize

		-- Current Tick
		subtreeitem:add(F_tick, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Tick: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

		-- Rx Current Tick
		subtreeitem:add(F_rxupdatetick, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Rx Update Tick: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

		-- Tx Current Tick
		subtreeitem:add(F_txupdatetick, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Tx Update Tick: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize

		-- Tx Power
		subtreeitem:add(F_txpower, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):int()))
		 	   :set_text("Tx Sync Power: " .. tvbuffer(ndx,fsize):int())
		ndx=ndx+fsize


		pinfo.cols.protocol = "PDS"
		pinfo.cols.info = tvbuffer(ndx,slen):string()

        end
        function pds.dissector(tvbuffer, pinfo, treeitem)
		local subtreeitem = treeitem:add(pds, tvbuffer)
		pdshead.dissector:call(tvbuffer:range(0,6):tvb(),pinfo,subtreeitem)
		pdsmsg.dissector:call(tvbuffer:range(6,2):tvb(),pinfo,subtreeitem)
		pdstail.dissector:call(tvbuffer:range(8,32):tvb(),pinfo,subtreeitem)
	end
	local dt = DissectorTable.get("udp.port");
	dt:add(9001, pds);
--	register_postdissector(pds)
end
