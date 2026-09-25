#!/usr/bin/env python3
import urllib.request
import json

new_key = "72f7c3027d8a89fea428bdb3de2645f96be73672ef14b581daeb92c444a7760c"
old_key = "b5a316fac45349013578e542a92527b31c5d2784e7d32a858434dc3598e6bcb8"
url = "https://www.virustotal.com/api/v3/domains/google.com"

print("="*70)
print("🧪 API KEY TEST - IP vs KEY SORUN TESPITI")
print("="*70)

print(f"\n[TEST 1] YENİ KEY: {new_key[:16]}...")
try:
    req = urllib.request.Request(url, headers={"x-apikey": new_key})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode('utf-8'))
        print(f"✅ YENİ KEY ÇALIŞIYOR!")
        print(f"   HTTP Status: {r.status}")
        print(f"   Domain scanned: {data['data']['id']}")
except urllib.error.HTTPError as e:
    print(f"❌ YENİ KEY HATA: HTTP {e.code}")
    if e.code == 429:
        print("   → Rate Limited")
    elif e.code == 403:
        print("   → Forbidden")
    elif e.code == 401:
        print("   → Invalid key")
except Exception as e:
    print(f"❌ YENİ KEY HATA: {str(e)}")

print("\n" + "-"*70)

print(f"\n[TEST 2] ESKİ KEY: {old_key[:16]}...")
try:
    req = urllib.request.Request(url, headers={"x-apikey": old_key})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode('utf-8'))
        print(f"✅ ESKİ KEY ÇALIŞIYOR!")
        print(f"   HTTP Status: {r.status}")
        print(f"   Domain scanned: {data['data']['id']}")
except urllib.error.HTTPError as e:
    print(f"❌ ESKİ KEY HATA: HTTP {e.code}")
    if e.code == 429:
        print("   → Rate Limited")
    elif e.code == 403:
        print("   → Forbidden")
    elif e.code == 401:
        print("   → Invalid key")
except Exception as e:
    print(f"❌ ESKİ KEY HATA: {str(e)}")

print("\n" + "="*70)
print("📊 SONUÇ ANALIZI:")
print("="*70)
print("""
Eğer:
  ✅ Her ikisi de çalışıyor   → IP sorunu YOK, KEY'ler hala geçerli
  ✅ Yeni OK, eski hata       → Eski key'ler BANNED (IP ban yedi)
  ❌ Her ikisi de hata        → IP BLOCKED (VT seni kara listeye aldı)
""")
