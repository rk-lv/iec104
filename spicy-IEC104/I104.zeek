@load base/protocols/conn
module I104;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## Record type containing the column fields of the I104 log.
	type Info: record {
		ts: time &log;
		#uid: string &optional &log;
		id: conn_id &log;
		## ASDU
		command_single: string &optional &log;
		command_double: string &optional &log;
	};
}

redef record connection += {
    # By convention, the name of this new field is the lowercase name
    # of the module.
    I104: Info &optional;
};

event zeek_init() &priority=5
    {
    # Create the stream. This adds a default filter automatically.
    Log::create_stream(I104::LOG, [$columns=Info, $path="I104"]);
    }


event I104::single_command(c: connection, info_obj_addr: int, scs: int)
{
	local command: string = "";
	if (scs == 0)
		{
			command = "OFF";
		}
	else if (scs == 1)
		{
			command = "ON";
		}
	else
		{
			command = "ON/OFF";
		}
	local rec: I104::Info = [$ts=network_time(), $id=c$id, $command_single=command];
    # hook set_session(c, originator_address);
    # local info = c$I104;
	# Write the log entry.
	c$I104 = rec;
	Log::write(I104::LOG, rec);
}

event I104::double_command(c: connection, info_obj_addr: int, dcs: int)
{
	local command: string = "";
	if (dcs == 1)
		{
			command = "OFF";
		}
	else if (dcs == 2)
		{
			command = "ON";
		}
	else
		{
			command = "ON/OFF";
		}

	local rec: I104::Info = [$ts=network_time(), $id=c$id, $command_double=command];
    # hook set_session(c, originator_address);
    # local info = c$I104;
	# Write the log entry.
	c$I104 = rec;
	Log::write(I104::LOG, rec);
}


# event connection_established(c: connection)
#     {
#     local rec: I104::Info = [$ts=network_time(), $id=c$id];
#
#     # Store a copy of the data in the connection record so other
#     # event handlers can access it.
#     c$I104 = rec;
#
#     Log::write(I104::LOG, rec);
#     }
