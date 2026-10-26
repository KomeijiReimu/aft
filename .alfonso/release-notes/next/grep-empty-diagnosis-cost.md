Empty `grep` and `glob` scope breakdowns now stop when the request runs out of time, so on very large checkouts they no longer keep using CPU in the background after the reply.
