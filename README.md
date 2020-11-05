# Loader
Kernel code gets ran by the um-process calling gHalDispatchTable[1] (hooked by the driver on load)



## How it works
  -authenticate / receive binary
  -decrypt binary
  -load vulnerable driver
  -map payload driver
  -wait for pubg
  -extend VAD of chosen module
  -inject binary into extended memory
  
  -km-um communication using a small "shared" memory buffer within the usermode process
  
  -clearing traces of the unloaded vulnerable driver
  
  

**Basically useless nowdays... Probably can still serve as some learning resource.**

**credits to @fisherprice from UC for cleaning MmUnloadedDrivers & PiDDBCacheTable structures (signatures should at least work for 1907 - 1909)**
