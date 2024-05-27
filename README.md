# (Generic) Burp Traffic Decryptor Extension

![image.png](https://images.viblo.asia/7fc11cd4-9bae-4454-af32-f4c0f531c3e1.png)

This extension creates a new tab called `Traffic Decryptor`, where you can define custom logic in Python to decrypt encrypted traffic. You can also define custom logic to re-encrypt edited values.

## How to Use
- Copy `logic.sample.py` to `logic.py`.
- Implement your logic for decrypting/encrypting and displaying decrypted data in this file. Check the file `example/logic.py` for an example.
- Use the Reload button in Traffic Decryptor each time you edit your logic to test it out without unloading/reloading the extension.

## Blog
- https://viblo.asia/p/viet-burp-extension-de-giai-ma-va-chinh-sua-traffic-da-ma-hoa-cua-mot-ung-dung-r1QLxwOoJAw
