https://www.freeformatter.com/xml-validator-xsd.html

# Dsigner instalacia

- nainstalovat veci z linky https://www.slovensko.sk/sk/na-stiahnutie 
- nainstalovat d.bridge 2 extension do prehliadaca
- mal by ist dsigner spustit z nasej appky a tlacidla sign.



# 4.zadanie - TODO list

**Overenie dátovej obálky:**

-   **DONE** koreňový element musí obsahovať atribúty xmlns:xzep a xmlns:ds podľa profilu XADES\_ZEP.

**Overenie XML Signature:**

-   **DONE** kontrola obsahu ds:SignatureMethod a ds:CanonicalizationMethod – musia obsahovať URI niektorého z podporovaných algoritmov pre dané elementy podľa profilu XAdES\_ZEP,
-   **DONE** kontrola obsahu ds:Transforms a ds:DigestMethod vo všetkých referenciách v ds:SignedInfo – musia obsahovať URI niektorého z podporovaných algoritmov podľa profilu XAdES\_ZEP,
-   **DONE**  **4.3.1.3 Core validation** (podľa špecifikácie XML Signature) – overenie hodnoty podpisu ds:SignatureValue a referencií v ds:SignedInfo:

    -   dereferencovanie URI, kanonikalizácia referencovaných ds:Manifest elementov a overenie hodnôt odtlačkov ds:DigestValue,
    -   kanonikalizácia ds:SignedInfo a overenie hodnoty ds:SignatureValue pomocou pripojeného podpisového certifikátu v ds:KeyInfo,

-   overenie ostatných elementov profilu XAdES\_ZEP, ktoré prináležia do špecifikácie XML Signature:

    -   **4.2.2** ds:Signature:
        -   **DONE** musí mať Id atribút,
        -   **DONE** musí mať špecifikovaný namespace xmlns:ds,
    -    Asi **DONE** 4.3.2 – overit - ds:SignatureValue element obsahuje skutočnú hodnotu elektronického podpisu a musí byť kódovaný v base64. ds:SignatureValue – musí mať Id atribút,
    -   **TODO** overenie existencie referencií v ds:SignedInfo a hodnôt atribútov Id a Type voči profilu XAdES\_ZEP pre:

        -   ds:KeyInfo element,
        -   ds:SignatureProperties element,
        -   xades:SignedProperties element,
        -   všetky ostatné referencie v rámci ds:SignedInfo musia byť referenciami na ds:Manifest elementy,

    -   overenie obsahu ds:KeyInfo:

        -   ESTE POZRIET musí mať Id atribút,
        -   **DONE** musí obsahovať ds:X509Data, ktorý obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName,
        -   **DONE** hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName súhlasia s príslušnými hodnatami v certifikáte, ktorý sa nachádza v ds:X509Certificate,

    -   overenie obsahu ds:SignatureProperties:

        -   **DONE** musí mať Id atribút,
        -   **DONE** musí obsahovať dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos,
        -   **DONE** obidva ds:SignatureProperty musia mať atribút Target nastavený na ds:Signature,

    -   **TODO** overenie ds:Manifest elementov:

        -   každý ds:Manifest element musí mať Id atribút,
        -   ds:Transforms musí byť z množiny podporovaných algoritmov pre daný element podľa profilu XAdES\_ZEP,
        -   ds:DigestMethod – musí obsahovať URI niektorého z podporovaných algoritmov podľa profilu XAdES\_ZEP,
        -   overenie hodnoty Type atribútu voči profilu XAdES\_ZEP,
        -   každý ds:Manifest element musí obsahovať práve jednu referenciu na ds:Object,

    -   **TODO** overenie referencií v elementoch ds:Manifest:

        -   dereferencovanie URI, aplikovanie príslušnej ds:Transforms transformácie (pri base64 decode),
        -   overenie hodnoty ds:DigestValue,

**TODO Overenie časovej pečiatky:**
-   overenie platnosti podpisového certifikátu časovej pečiatky voči času UtcNow a voči platnému poslednému CRL.
-   overenie MessageImprint z časovej pečiatky voči podpisu ds:SignatureValue

**TODO Overenie platnosti podpisového certifikátu:**
-   overenie platnosti podpisového certifikátu dokumentu voči času T z časovej pečiatky a voči platnému poslednému CRL.

