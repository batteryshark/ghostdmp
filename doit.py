# Quick Binding against Memory Dumper
from ctypes import *

TARGET_PID = 768


dump_dll = cdll.LoadLibrary("libghostdmp.dll")
dump_dll.dump_process_memory.argtypes = [c_uint32,POINTER(POINTER(c_ubyte)),POINTER(c_uint64)]

def dump_process(pid):
	data_ptr = POINTER(c_ubyte)()
	data_len = c_uint64(0)

	if(not dump_dll.dump_process_memory(TARGET_PID,byref(data_ptr),byref(data_len))):
		print("Dump Failed :(")
		exit(-1)

	return cast(data_ptr,POINTER(c_ubyte * data_len.value))[0]



if(__name__=="__main__"):
	buffer = dump_process(TARGET_PID)
	print("Dump Size is %d Bytes" % len(buffer))
	with open("Output.dmp","wb") as g:
		g.write(buffer)
	
	print("Dump Written - SEE YOU!")