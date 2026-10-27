Disk-limit eviction no longer keeps an idle view because a background cleanup pass happened to be reading its pointer at that moment; it waits for that short read to finish.
