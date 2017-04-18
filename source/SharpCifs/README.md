### INTRODUCTION


SharpCifs is a port of JCIFS to C# for make your Windows Phone 8.1 (Silverlight) apps capable to 
work with network shares. 

It was ported using the Lluis Sanchez's already compiled Sharpen (found at 
https://github.com/mono/ngit/tree/master/gen/plugins) and applying a lot of changes to make the port works.

### SETTINGS

All client settings are same as jCifs, you can take a look at: https://jcifs.samba.org/src/docs/api/overview-summary.html#scp

If you want to use the NetBIOS name resolution you must set the "jcifs.netbios.laddr" with phone's IP address, and "jcifs.netbios.baddr" with the broadcast address.


### NOTES

- The JCIFS version ported to C# was 1.3.17.
- By default I have disabled the DFS support due a problems with Microsoft accounts when you try to connect to your Windows 8.1. You can enable it by setting to true the "jcifs.smb.client.enabledfs" property. 
- I added a new method GetHosts on NbtAddress class to find hosts on small networks. 


### LINKS

The original Java project can be found at: http://jcifs.samba.org
