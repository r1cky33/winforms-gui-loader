# ultinject_krnl
driver interface with 

  -dll-injection capabilities
  
  -km-um communication using an small "shared" memory buffer in the usermode process
  
  -clearing traces of the unloaded vulnerable driver

this whole shit is coded by me and was ALOT OF WORK. so pls treat it with respect xD

credits to @fisherprice from UC for cleaning MmUnloadedDrivers & PiDDBCacheTable structures (signatures should at least work for 1803-1903)
