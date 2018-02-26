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

	-- Create the new fields, and associate to the protocol
        local F_type = ProtoField.uint8("pds.type", "Type")
        local F_version = ProtoField.uint8("pds.version", "Version")
        local F_length = ProtoField.uint16("pds.len", "Length")
        local F_seqno = ProtoField.uint16("pds.seqno", "Sequence")

        local F_rxnoise = ProtoField.int16("pds.rxnoise", "Rx Noise")
        local F_rxlock = ProtoField.uint16("pds.rxlock", "Rx Lock")
        local F_sync = ProtoField.string("pds.sync", "Sync")
        local F_l2 = ProtoField.string("pds.l2", "L2 Status")
        local F_l3 = ProtoField.string("pds.l3", "L3 Status")
        local F_l3 = ProtoField.string("pds.l3", "L3 Status")
        local F_mute = ProtoField.string("pds.mute", "Mute")
        local F_mutein = ProtoField.string("pds.mute", "Mute Input")
        local F_mode = ProtoField.string("pds.mode", "Mode")
 
        local F_rxlevel = ProtoField.int16("pds.rxlevel", "Rx Level")
        local F_txcapa = ProtoField.string("pds.txcapa", "Tx Cap A")
        local F_txcapb = ProtoField.string("pds.txcapb", "Tx Cap B")
        local F_txcapc = ProtoField.string("pds.txcapc", "Tx Cap C")
        local F_tick = ProtoField.string("pds.rxtick", "Rx Tick")
        local F_updatetick = ProtoField.string("pds.txtick", "Tx Tick")
        local F_txpower = ProtoField.string("pds.txpower", "Tx Power")

        pds.fields = {F_type, F_verson, F_length, F_seqno,
             F_rxnoise, F_rxlock, F_sync, F_l2, F_l3,
	     F_mute, F_mutein, F_mode, F_rxlevel, F_txcapa, F_txcapb,
	     F_txcapc, F_tick, F_updatetick, F_txpower}

	-- Define the dissector function
        function pds.dissector(tvbuffer, pinfo, treeitem)

		local ndx=0;
		local fsize=1;

		-- Store the top of the analysis tree
		local subtreeitem = treeitem:add(pds, tvbuffer)

		--
		-- Type
		subtreeitem:add(F_type, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):le_uint()))
			   :set_text("Type: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Version
		subtreeitem:add(F_version, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):le_uint()))
			   :set_text("Version: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Length Unit
		fsize=2
		subtreeitem:add(F_length, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):le_uint()))
			   :set_text("Length: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Seqno
		subtreeitem:add(F_seqno, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Sequence: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Rx Noise
		fsize=1
		subtreeitem:add(F_rxnoise, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Rx Noise: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Rx Lock
		subtreeitem:add(F_rxlock, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Rx Lock: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Sync Status
		subtreeitem:add(F_sync, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Sync Status: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- L2 Status
		subtreeitem:add(F_l2, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("L2 Status: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- L3 Status
		subtreeitem:add(F_l3, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("L3 Status: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 


		-- Mute 
		subtreeitem:add(F_mute, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Mute Open Amip: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 


		-- Mute In Status
		subtreeitem:add(F_mutein, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Mute Discrete In: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Operational Mode 
		subtreeitem:add(F_mode, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Operational Mode: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 


		ndx=ndx+2
		-- Rx Level 
		fsize=4
		subtreeitem:add(F_rxlevel, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):int()))
			   :set_text("Rx Level: " .. tvbuffer(ndx,fsize):int())
		ndx=ndx+fsize 

		-- Tx Cap A  
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

		-- Current Tick  
		subtreeitem:add(F_updatetick, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
			   :set_text("Update Tick: " .. tvbuffer(ndx,fsize):uint())
		ndx=ndx+fsize 

		-- Tx Power  
		-- subtreeitem:add(F_txpower, tvbuffer(ndx,fsize), (tvbuffer(ndx,fsize):uint()))
		-- 	   :set_text("Tx Power: " .. tvbuffer(ndx,fsize):uint())
		-- ndx=ndx+fsize 


		pinfo.cols.protocol = "pds"
		pinfo.cols.net_dst = "PDS"
		pinfo.cols.info = tvbuffer(ndx,slen):string() 

        end
	local dt = DissectorTable.get("udp.port");
	dt:add(9001, pds);
--	register_postdissector(pds)
end
