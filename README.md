### Reveal 2.0 is here!
Reveal 2.0 takes a two phase approach to finding hidden LKM rootkits. The first phase includes scanning for a response to a kill signal (1-64). If a rootkit is found, it is made visible so that it can be safely removed. In phase two, /proc/modules is cross checked with sysfs to find discrepancies. It also checks initstate, ignoring built-in modules and identifies dynamically loaded modules, like rootkits.

First, lets's compile reveal
```
gcc -o reveal2 reveal2.c
```
Ready to run reveal and find hidden LKM rootkits!

```
# sudo ./reveal2
[*] Phase 1: Beginning isolated 1-64 signal scan for hidden LKMs...
[*] Phase 2: Beginning SYSFS cross-reference tracking...

[CRITICAL] Hidden Rootkit Revealed Via Signal 63:
           -> Target Identity: diamorphine
           -> Remediation: sudo rmmod diamorphine

[*] Note: Rootkit exposed and localized via signal validation mechanisms.
```
You can also skip a phase like this
```
sudo ./reveal2 --skip-phase1
```
If you get a result that indicates a kill signal could not be found, you should reboot and run the scan again. This will resolve the problem if a rootkit has not been made persistent. If, after rebooting, the scan still indicates the presence of a rootkit, it is being made persistent by some other means. Check my paper below. In particular, the sectiton titled "What if a reboot doesn't clear the kernel of suspected rootkit?" While these suggestions do not include every possibility, they do include common methods for making a module persistent.

You might also enjoy reading <a href="https://carls0n.github.io">defeating LKM and LD_PRELOAD rootkits for fun and profit</a>
