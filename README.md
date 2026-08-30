# Secure Audit Logs Hash Chain Python

This example demonstrates how to secure audit logs using a hash chain, a fundamental concept for ensuring data integrity. Each log entry is cryptographically linked to the previous one by including the previous entry's hash in its own data, which is then hashed to create its unique identifier. Any modification to a past log entry will break the hash chain, immediately indicating tampering.

## Language

`python`

## How to Run

Save the code as `main.py`.
Run from your terminal: `python main.py`

## Original Article

This example accompanies the Turkish article: [Denetim Kayıtlarınızın Güvenliğini Hash Zinciriyle Nasıl Sağlarsınız?](https://fatihsoysal.com/blog/denetim-kayitlarinizin-guvenligini-hash-zinciriyle-nasil-saglarsiniz/).

## License

MIT — see [LICENSE](LICENSE).
