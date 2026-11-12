Two distinct root causes in `nmreq_option_parsekeys()` (libnetmap/nmreq.c); both defects the run reports for this target.
Each is an independent unchecked `scan++` past the string terminator, so each needs its own fix:
`parsekeys-key-without-value/` (line 449) and `parsekeys-trailing-comma/` (line 425).
