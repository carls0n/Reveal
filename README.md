# Reveal
Reveal was written to find ANY hidden LKM rootkit. Guaranteed! It doesn't matter what method is used to hide the LKM rootkit, Reveal will find it!
Even modules hidden using kobj will be easily found. Even LKM rootkits that hide from memory scanning will be found!
Reveal doesnt use ANY of those methods to find hidden LKM rootkits! Unlike any other method that attempts to find hidden LKM rootkits, reveal uses kill signals to identify installed and hidden LKM rootkits!
<br><br>
First, lets's compile reveal
```
gcc -o reveal reveal.c
```
Ready to run reveal and find any hidden LKM rootkits!
```
./reveal
```

Reveal will quickly find any hidden rootkit and unhide the module so that you can safely remove the rootkit.
