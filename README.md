# Reveal
Reveal was written to find most LKM rootkits by utilizing signal scanning.
Even modules hidden using kobj will be easily found. Even LKM rootkits that hide from memory scanning will be found!
Reveal doesnt use ANY of those methods to find hidden LKM rootkits! Reveal uses kill signals (1-64) to identify installed and hidden LKM rootkits that use a kill signal to toggle visibility.
<br><br>
First, lets's compile reveal
```
gcc -o reveal reveal.c
```
Ready to run reveal and find hidden LKM rootkits!
```
./reveal
```

You can use my Advanced Ultra Stealth <a href="https://github.com/carls0n/rootkit">Hide Only LKM</a> for research.
