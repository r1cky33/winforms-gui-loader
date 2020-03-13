## Loader Tarab.xyz

Secure Tarab Loader for up2date BE/EAC versions. The kernelmode code gets executed by the UM-process that calls gHalDispatchTable[1] (hooked by the driver on load)

##How it works

  -authenticate
  -decrypt binary
  -map vulnerable driver
  -map payload driver
  -wait for pubg
  -extend 7z.dll
  -inject binary in extendet region
  
  -km-um communication using a small "shared" memory buffer within the usermode process
  -clearing traces of the unloaded vulnerable driver

this whole shit is coded by me and was ALOT OF WORK. so pls treat it with respect xD

credits to @fisherprice from UC for cleaning MmUnloadedDrivers & PiDDBCacheTable structures (signatures should at least work for 1907)
