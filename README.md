<img width="1370" height="798" alt="reveal" src="https://github.com/user-attachments/assets/77b1dd21-932e-4627-964c-de80443fc279" />

Reveal was written to find LKM rootkits by using signal scanning.
Even modules hidden using kobj will be easily found. Even LKM rootkits that hide from memory scanning will be found!
Reveal doesnt use ANY of those methods to find hidden LKM rootkits! Reveal uses kill signals (1-64) to identify installed and hidden LKM rootkits that use a kill signal (1-64) to toggle visibility. A couple of rootkit examples that can be found via signal scanning are <a href="https://github.com/m0nad/Diamorphine">Diamorphine</a> and <a href="https://github.com/brosck/Rebellion">Rebellion</a><br><br>
Unfortunately, it is trivial to change this behavior of rootkits and evade signal scanning. This tool should not be thought of as a comprehensive solution but rather another tool in your arsenal.
<br><br>
First, lets's compile reveal
```
gcc -o reveal reveal.c
```
Ready to run reveal and find hidden LKM rootkits!
```
./reveal
```
