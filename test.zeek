global test : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name=="USER-AGENT")
    {
        if(c$id$orig_h in test)
        {
            if(to_lower(value) !in test[c$id$orig_h])
            {
                add test[c$id$orig_h][to_lower(value)];
            }
        }
        else
        {
            test[c$id$orig_h]=set(to_lower(value));
        }
    }
}
event zeek_done()
{
	for (Addr, Set in test)
	{
		if(|Set|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}
