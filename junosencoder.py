#!/usr/bin/python

#############################################################################
## this lovely script was painfully ported
## by matt hite (mhite@hotmail.com), who knows
## very little perl
##
## Updated by Olen to support both encode and decode and work under Python3
##
##
## original: http://search.cpan.org/dist/Crypt-Juniper/lib/Crypt/Juniper.pm
## requires python 3
##
## version 2.0
##

import sys
from random import randrange
from passlib.hash import sha256_crypt, sha512_crypt


class JunosEncoder:
    #################################################################
    ## globals
    
    MAGIC = "$9$"
    
    ###################################
    ## letter families
    
    FAMILY = ["QzF3n6/9CAtpu0O", "B1IREhcSyrleKvMW8LXx", "7N-dVbwsY2g4oaJZGUDj", "iHkq.mPf5T"]
    EXTRA = {}
    for x, item in enumerate(FAMILY):
        for c in item:
            EXTRA[c] = 3 - x
    
    

    ###################################
    ## forward and reverse dictionaries
    
    NUM_ALPHA = [x for x in "".join(FAMILY)]
    ALPHA_NUM = {}
    for x, item in enumerate(NUM_ALPHA):
        ALPHA_NUM[item] = x

    ###################################
    ## encoding moduli by position
    
    ENCODING = [[1, 4, 32], [1, 16, 32], [1, 8, 32], [1, 64], [1, 32], [1, 4, 16, 128], [1, 32, 64]]
    

    def __init__(self, string, salt=None, sha256_rounds=None, sha512_rounds=None):
        self.salt = salt
        self.sha256_rounds = sha256_rounds
        self.sha512_rounds = sha512_rounds
        if string.startswith("$9$"):
            self.secret = string
        else:
            self.plaintext = string


    @property
    def secret(self):
        return self._encrypted

    @secret.setter
    def secret(self, string):
        self._decrypted = self.juniper_decrypt(string)
        self._encrypted = string
        
    @property
    def plaintext(self):
        return self._decrypted

    @plaintext.setter
    def plaintext(self, string):
        self._decrypted = string
        self._encrypted = self.juniper_encrypt(string, salt=self.salt)

    @property
    def sha256(self):
        return sha256_crypt.hash(self._decrypted, salt=self.salt, rounds=self.sha256_rounds)

    @property
    def sha512(self):
        return sha512_crypt.hash(self._decrypted, salt=self.salt, rounds=self.sha256_rounds)

    def juniper_decrypt(self, crypt):
        chars = crypt.split(JunosEncoder.MAGIC, 1)[1]
        first, chars = self._nibble(chars, 1)
        toss, chars = self._nibble(chars, self.EXTRA[first])
        prev = first
        decrypt = ""
        while chars:
            decode = self.ENCODING[len(decrypt) % len(self.ENCODING)]
            nibble, chars = self._nibble(chars, len(decode))
            gaps = []
            for i in nibble:
                g = self._gap(prev, i)
                prev = i
                gaps += [g]
            decrypt += self._gap_decode(gaps, decode)
        return decrypt
    
    def juniper_encrypt(self, secret, salt=None):
        if not salt:
            salt = self._randc(1)
    
        rand = self._randc(self.EXTRA[salt])
    
        # salt = "K"
        # rand = "xr"
    
        prev = salt;
        crypt = f"{JunosEncoder.MAGIC}{salt}{rand}";
    
        for (pos, char) in enumerate(secret):
            encode = self.ENCODING[pos % len(self.ENCODING)]
            crypt += self._gap_encode(char, prev, encode)
            prev = crypt[-1]
    
        return crypt;
    
        
    def _nibble(self, cref, length):
        nib = cref[0:length]
        rest = cref[length:]
        if len(nib) != length:
            print("Ran out of characters: hit '%s', expecting %s chars" % (nib, length))
            sys.exit(1)
        return nib, rest


    def _gap(self, c1, c2):
        return (self.ALPHA_NUM[str(c2)] - self.ALPHA_NUM[str(c1)]) % (len(self.NUM_ALPHA)) - 1


    def _gap_decode(self, gaps, dec):
        num = 0
        if len(gaps) != len(dec):
            print("Nibble and decode size not the same!")
            sys.exit(1)
        if dec[0] > 1:
            dec.reverse()
        # print(dec)
        for x in range(0, len(gaps)):
            num += gaps[x] * dec[x]
            # print("Num:", num)
        return chr(num % 256)

    ## return a random number of characters from our alphabet
    def _randc(self, cnt=0):
        r = '';
    
        while cnt > 0:
            r += self.NUM_ALPHA[randrange(len(self.NUM_ALPHA))]
            cnt = cnt - 1
    
        return r
    
    ## encode a plain-text character with a series of gaps,
    ## according to the current encoder.
    def _gap_encode(self, pc, prev, enc):
        unicode_char = ord(pc)
    
        crypt = '';
        gaps = [];
    
        if enc[0] == 1:
            enc.reverse()
        for mod in enc:
            gaps.append(int(unicode_char/mod))
            # print("Mod:", mod, "Char: ", str(int(unicode_char/mod)), "\n");
            unicode_char %= mod
    
        gaps.reverse()
        for gap in gaps:
            gap += self.ALPHA_NUM[prev] + 1
            c = self.NUM_ALPHA[gap % len(self.NUM_ALPHA)]
            prev = c
            crypt += c
            # print("C", c, crypt)
    
        return crypt;


# Filter for ansible
#
# save this file in $ansible/filter_plugins/
#
# example usage in a jinja2 template:
#
# {% set password = "MySecretPassword" | junosencoder %}
#
# set system radius-server 1.2.3.4 secret "{{ password.secret }}"
# set system root-authentication encrypted-password "{{ password.sha512 }}"
#
 
class FilterModule (object):
    def filters(self):
        return {
            "junosencoder": self.junosencoder
        }
 
    def junosencoder(self, value):
        encoder = JunosEncoder(value)
        result = {
            'plaintext': encoder.plaintext,
            'secret': encoder.secret,
            'sha256': encoder.sha256,
            'sha512': encoder.sha512,
        }
        return result

def main():
    if len(sys.argv) == 2:
        string = sys.argv[1]
    else:
        print(f"Usage: {sys.argv[0]} <plaintext|encoded>")
        sys.exit(1)

    e1 = JunosEncoder(string)
    print("Plaintext: %s" % e1.plaintext)
    print("Secret: %s" % e1.secret)
    print("Sha256 hash: %s" % e1.sha256)
    print("Sha512 hash: %s" % e1.sha512)



if __name__ == "__main__":
    main()
