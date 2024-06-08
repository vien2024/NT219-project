

# This file was *autogenerated* from the file wiener.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0 = Integer(0); _sage_const_2 = Integer(2); _sage_const_1 = Integer(1); _sage_const_6727075990400738687345725133831068548505159909089226909308151105405617384093373931141833301653602476784414065504536979164089581789354173719785815972324079 = Integer(6727075990400738687345725133831068548505159909089226909308151105405617384093373931141833301653602476784414065504536979164089581789354173719785815972324079); _sage_const_4805054278857670490961232238450763248932257077920876363791536503861155274352289134505009741863918247921515546177391127175463544741368225721957798416107743 = Integer(4805054278857670490961232238450763248932257077920876363791536503861155274352289134505009741863918247921515546177391127175463544741368225721957798416107743); _sage_const_5928120944877154092488159606792758283490469364444892167942345801713373962617628757053412232636219967675256510422984948872954949616521392542703915478027634 = Integer(5928120944877154092488159606792758283490469364444892167942345801713373962617628757053412232636219967675256510422984948872954949616521392542703915478027634); _sage_const_68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605 = Integer(68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605)
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA

# effective when d (private key) is small to n
def wiener(e, n):
    # Convert e/n into a continued fraction
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    for kd in convergents:
        k = kd.numerator()
        d = kd.denominator()
        # Check if k and d meet the requirements
        if(k == _sage_const_0  or d%_sage_const_2  == _sage_const_0  or (e*d % k) != _sage_const_1 ):
            continue
        phi = (e*d - _sage_const_1 )/k
        # Create the polynomial
        x = PolynomialRing(RationalField(), 'x').gen()
        f = x**_sage_const_2  - (n-phi+_sage_const_1 )*x + n
        roots = f.roots()
        # Check if polynomial as two roots
        if len(roots) != _sage_const_2 :
            continue
        # Check if roots of the polynomial are p and q
        p,q = int(roots[_sage_const_0 ][_sage_const_0 ]), int(roots[_sage_const_1 ][_sage_const_0 ])
        if p*q == n:
            return d
    return None

def get_pubkey(f):
    with open(f) as pub:
        key = RSA.importKey(pub.read())
    return (key.n, key.e)

def get_ciphertext(f):
    with open(f, 'rb') as ct:
        return bytes_to_long(ct.read())

# Test to see if our attack works
if __name__ == '__main__':
    n = _sage_const_6727075990400738687345725133831068548505159909089226909308151105405617384093373931141833301653602476784414065504536979164089581789354173719785815972324079 
    e = _sage_const_4805054278857670490961232238450763248932257077920876363791536503861155274352289134505009741863918247921515546177391127175463544741368225721957798416107743 
    c = _sage_const_5928120944877154092488159606792758283490469364444892167942345801713373962617628757053412232636219967675256510422984948872954949616521392542703915478027634 
    
    N, e = get_pubkey('./key.pub')
    print(f"N: {N}")
    print("\n")
    print(f"Public key e: {e}")
    print("\n")
    e = _sage_const_68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605 
    #n = 573177824579630911668469272712547865443556654086190104722795509756891670023259031275433509121481030331598569379383505928315495462888788593695945321417676298471525243254143375622365552296949413920679290535717172319562064308937342567483690486592868352763021360051776130919666984258847567032959931761686072492923

    ct = get_ciphertext("flag.enc")
    d = wiener(e,N)
    print(f"Private Key: {d}")
    #assert not d is None, "Wiener's attack failed :("
    print(long_to_bytes(int(pow(ct,d,n))))

