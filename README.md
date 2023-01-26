# Encode/decode Juniper $9$ secrets

This tool allows you to encode and decode junos "$9$"-secrets (e.g. radius secrets etc. in the config).

Feed it with either plaintext or an encoded string.

The tool can be used in 3 ways:

## 1. Directly as a simple encoder/decoder:

```
$ ./junosencoder.py MySecret
Plaintext: MySecret
Secret: $9$86gX-bZUHm5zVwgJUDPf369COR
Sha256 hash: $5$rounds=535000$fM65GDuhRV7DNvnb$WN2r65vp/2zUCeNFVaQmA0C.hFcgorFtkua6wRnu8d3
Sha512 hash: $6$rounds=656000$iWcJHP5.7l5H3usC$0OmX6BzoXHB.SbkcAGvh7NDKETu3pnwvdgaLaUQXvho/RBdmzI.iSadWEHkFcAkOqx9LigrGUqahidchM9apx/
```

or

```
$ ./junosencoder.py '$9$NqVgaji.fQnfTuBEyW84aZjHmTzntpBGD9p0BSy24aJiqTQn6A0z3'
Plaintext: VeryLongSecretText
Secret: $9$NqVgaji.fQnfTuBEyW84aZjHmTzntpBGD9p0BSy24aJiqTQn6A0z3
Sha256 hash: $5$rounds=535000$5fdAcoL.gNZgoGSm$Ba48kpsfuKSC0FkDhCMEmYwMcLrFja0/lbsJKZ3pI45
Sha512 hash: $6$rounds=656000$R02lErgVTsNLBB99$n.2DS18J9hmNTrllCW0iLoyaxciuEm2PUN2C3dZqkL17xoLowKkrLChZoxCk55NkT4/Kh7zHmWZ9cGz0QGpH3/
```

## 2. As a module
```
from junosencoder import JunosEncoder

e1 = JunosEncoder("MySecret")

print("Secret:", e1.secret)
print("Plaintext:", e1.plaintext)
print("SHA256:", e1.sha256)
print("SHA512:", e1.sha512)

```

## 3. As an Ansible filter
Copy junosencoder.py to e.g. `ansible/playbooks/filter_plugins/`

Use it in your jinja2-templates:
```
{% set radius_secret = "RadiusSecret" | junosencoder %}
set system radius-server {{ radius_server_hostname }} secret "{{ radius_secret.secret }}"

```



Built on https://github.com/mhite/junosdecode

Which is baed on https://metacpan.org/pod/Crypt::Juniper


