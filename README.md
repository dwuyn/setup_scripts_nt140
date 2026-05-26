# Firewall Misconfiguration Lab Demo

Lab nay tai hien co che source-port bypass trong paper:

- `Beyond the Horizon: Uncovering Hosts and Services Behind Misconfigured Firewalls`
- File paper trong repo: `oakland25_firewall_misconfig.pdf`

Muc tieu cua lab:

- dung 1 moi truong nho, do that bang Docker
- cho thay cach firewall stateless match theo `--sport 80` va `--sport 53` bi loi
- cho thay su khac nhau giua 3 mode `flawed`, `flags`, `secure`
- scan va audit bang script de thu duoc ket qua do that, khong dung simulated data

Sau lan verify cuoi, lab thuong duoc de o `secure` mode. Neu muon demo bypass ngay, can chuyen ve:

```bash
bash scripts/labsetup/setup.sh mode flawed
```

## 1. Tong quan setup hien tai

### Topology

Lab co 3 container:

- `attacker`: `172.20.1.2`
- `firewall_node`: `172.20.1.254` o mang outside va `172.20.2.254` o mang inside
- `victim`: `172.20.2.2`

Hai Docker network:

- `firewall_outside`: `172.20.1.0/24`
- `firewall_inside`: `172.20.2.0/24`

Flow packet:

```text
attacker (172.20.1.2)
    |
    v
firewall_node (172.20.1.254 / 172.20.2.254)
    |
    v
victim (172.20.2.2)
```

Route duoc ep tay de moi traffic tu attacker sang victim phai di qua firewall.

### Service map

Victim dang mo 6 service:

- Public baseline:
  - `80/tcp` HTTP
  - `53/udp` DNS responder toi gian
- Protected services:
  - `22/tcp` SSH
  - `27017/tcp` MongoDB banner server
  - `3389/tcp` RDP banner server
  - `123/udp` NTP responder toi gian

Y nghia:

- `public`: service co chu dich de lo ra ngoai
- `protected`: service dang le phai bi an sau firewall

## 2. Cau truc repo

```text
oakland25_firewall_misconfig.pdf
scripts/
  labsetup/
    setup.sh
  scanner/
    bypass_scanner.py
    compare_rules.py
    firewall_audit.py
  results/
    scan_results.json
    comparison_results.json
    audit_results.json
```

Y nghia tung nhom file:

- `setup.sh`: dung, xoa, doi mode firewall
- `bypass_scanner.py`: scanner workflow 3 pha
- `compare_rules.py`: chay scanner tren 3 mode va tong hop metrics
- `firewall_audit.py`: audit live iptables rules trong firewall container
- `results/*.json`: ket qua cua lan chay gan nhat

## 3. Prerequisites

Can co:

- Docker daemon dang chay
- `python3`

Khong can cai Scapy hay cong cu ngoai tren host. Scanner se tu `docker exec` vao container `attacker`.

## 4. Chi tiet file `scripts/labsetup/setup.sh`

Day la script dieu phoi toan bo lab.

### Chuc nang

Script ho tro 4 lenh:

```bash
bash scripts/labsetup/setup.sh up
bash scripts/labsetup/setup.sh mode flawed
bash scripts/labsetup/setup.sh status
bash scripts/labsetup/setup.sh down
```

### `up` lam gi

Khi chay:

```bash
bash scripts/labsetup/setup.sh up
```

script se:

1. Kiem tra `docker` va `python3`
2. Xoa container/network cu neu co
3. Tao 2 Docker network
4. Dung `victim`
5. Cho den khi ca 6 service tren victim thuc su listen xong
6. Dung `firewall_node`
7. Dung `attacker`
8. Gan route de traffic phai di qua firewall
9. Apply mode mac dinh la `flawed`

### `victim` hoat dong the nao

Trong container `victim`, script khoi dong:

- `sshd` tren `22/tcp`
- `python3 -m http.server` tren `80/tcp`
- 2 TCP banner server:
  - `27017/tcp` tra `MongoDB 4.2.0 (INTERNAL)`
  - `3389/tcp` tra `Windows RDP 7.0 EOL`
- 2 UDP responder:
  - `53/udp` tra `DNS-LAB-OK`
  - `123/udp` tra `NTP-LAB-OK`

Service readiness duoc check bang `ss -lntup`. Neu chua du 6 listener, script se doi.

### `firewall_node` hoat dong the nao

Container nay la router/firewall:

- bat `net.ipv4.ip_forward=1`
- cai `iptables`, `iproute2`, `conntrack`
- mo 2 NIC logic qua 2 Docker network

Moi lan doi mode, script se:

- flush `conntrack`
- flush rules cu
- dat `FORWARD DROP`

Ly do flush `conntrack`: tranh state leak giua cac lan test, nhat la UDP.

### `attacker` hoat dong the nao

Container nay la vantage point de scan:

- co IP `172.20.1.2`
- duoc mount repo vao `/lab`
- scanner khi chay tren host se tu nhay vao day bang `docker exec`

Ly do:

- can bind `source port 80` va `source port 53`
- muon do packet flow tu dung vi tri ben ngoai firewall

### 3 firewall mode

#### `flawed`

Mode loi co chu dich de demo bypass.

Rules logic:

- allow traffic tu inside ra outside
- allow inbound `80/tcp`
- allow inbound `53/udp`
- allow moi TCP packet co `--sport 80`
- allow moi UDP packet co `--sport 53`
- drop phan inbound con lai

Y nghia:

- attacker co the mo ket noi moi vao service an, chi can gia lam packet "reply" tu HTTP hoac DNS

#### `flags`

Mode giam nhe cho TCP nhung van de loi UDP.

Rules logic:

- van public `80/tcp` va `53/udp`
- van allow outbound inside -> outside
- TCP rule sai duoc doi thanh:
  - `--sport 80 --tcp-flags SYN,RST,ACK ACK`
- UDP `--sport 53` van con

Y nghia:

- TCP bypass bi chan, vi packet mo ket noi moi dung `SYN`, khong co `ACK`
- UDP bypass van song

#### `secure`

Mode dung theo huong stateful.

Rules logic:

- allow `ESTABLISHED,RELATED`
- allow `NEW` tu inside ra outside
- allow public `80/tcp`
- allow public `53/udp`
- drop inbound con lai

Y nghia:

- chi packet thuoc ket noi da ton tai moi duoc vao
- packet moi gia reply tu source port `80` hay `53` se bi chan

## 5. Chi tiet file `scripts/scanner/bypass_scanner.py`

Day la scanner workflow 3 pha.

### Cach script chay

Neu ban goi tu host:

```bash
python3 scripts/scanner/bypass_scanner.py
```

script se:

1. kiem tra xem no dang chay trong `attacker` chua
2. neu chua, tu dong:

```text
docker exec attacker python3 /lab/scripts/scanner/bypass_scanner.py
```

Nghia la ban khong can tu vao container.

### Service ma scanner quan tam

Scanner scan 6 service co dinh:

- `ssh` -> `22/tcp`
- `http` -> `80/tcp`
- `mongodb` -> `27017/tcp`
- `rdp` -> `3389/tcp`
- `dns` -> `53/udp`
- `ntp` -> `123/udp`

### 3 pha cua scanner

#### Phase 1: Identify

Scanner dung designated source port:

- TCP dung `source port 80`
- UDP dung `source port 53`

No thu tiep can service tu source port dac biet nay.

Neu designated probe vao duoc, service tro thanh candidate.

#### Phase 2: Probe

Scanner lay dau hieu application-level:

- SSH doc banner `SSH-2.0-...`
- HTTP gui `HEAD / HTTP/1.0`
- MongoDB doc banner text
- RDP doc banner text
- DNS/NTP gui UDP payload va doc response

Muc dich:

- chung minh service la co that
- khong chi thay port mo ma con thay loai service

#### Phase 3: Validate

Scanner scan lai cung service nhung bang high source ports:

- `45123`
- `52847`
- `61204`

Phan loai:

- neu high-port vao duoc -> `public`
- neu designated vao duoc nhung high-port khong vao duoc -> `affected`
- neu designated khong vao duoc -> `closed`
- neu bind source port that bai hay runtime issue -> `inconclusive`

### Cach doc ket qua

Vi du:

```text
ssh 22/tcp -> affected
```

nghia la:

- tu source port `80`, scanner vao duoc SSH
- tu high port thong thuong, scanner khong vao duoc
- vay SSH dang bi firewall expose sai

Vi du:

```text
http 80/tcp -> public
```

nghia la:

- service nay dung la public
- khong phai hidden service bi lo

### Output cua scanner

Script ghi ket qua vao:

```text
scripts/results/scan_results.json
```

Luu y:

- file nay chi phan anh lan scan gan nhat
- neu lab dang o `secure`, file se cho thay `affected=0`

## 6. Chi tiet file `scripts/scanner/compare_rules.py`

Script nay chay scanner tren ca 3 mode de so sanh.

### Flow hoat dong

No se tu dong:

1. `mode flawed`
2. chay scanner
3. `mode flags`
4. chay scanner
5. `mode secure`
6. chay scanner
7. tong hop ket qua

### Metric hien tai

Protected set co dinh:

- `22/tcp`
- `27017/tcp`
- `3389/tcp`
- `123/udp`

Public baseline set co dinh:

- `80/tcp`
- `53/udp`

Metric:

- `detection_rate` = `affected protected services / 4`
- `false_positive_rate` = `public candidates / all candidates sau identify+probe`
- `observable_expansion_pct` = `affected / 2 * 100`
- `lab_only_risk_score` = diem nguy co trong lab, khong phai metric cua paper

### Ket qua expected cua lab

Neu moi thu dung, comparison report se ra:

- `flawed`: `affected=4`, `public=2`
- `flags`: `affected=1`, `public=2`
- `secure`: `affected=0`, `public=2`

### Output

Ket qua ghi vao:

```text
scripts/results/comparison_results.json
```

File nay la `provenance = measured`, tuc duoc do that tu lab.

## 7. Chi tiet file `scripts/scanner/firewall_audit.py`

Script nay audit live iptables rules cua `firewall_node`.

### Cach hoat dong

Mac dinh script se:

1. `docker exec firewall_node iptables -S`
2. parse rules
3. tim misconfiguration
4. in report va ghi JSON

Neu khong doc duoc live rules, no moi fallback sang sample.

### Cac loi ma audit tim

- source-port bypass rule TCP
  - vi du `--sport 80`
- source-port bypass rule UDP
  - vi du `--sport 53`
- stateless UDP reply rule
- broad stateless TCP rule khong co ACK filtering
- khong co stateful tracking

### Expected theo tung mode

- `flawed`: co findings
- `flags`: con findings lien quan UDP, khong con TCP SYN bypass
- `secure`: `0 findings`

### Output

Ket qua ghi vao:

```text
scripts/results/audit_results.json
```

## 8. Cach chay tung script

### Dung lab

```bash
bash scripts/labsetup/setup.sh up
```

### Xem trang thai hien tai

```bash
bash scripts/labsetup/setup.sh status
```

### Chuyen mode firewall

```bash
bash scripts/labsetup/setup.sh mode flawed
bash scripts/labsetup/setup.sh mode flags
bash scripts/labsetup/setup.sh mode secure
```

### Chay scanner 1 mode hien tai

```bash
python3 scripts/scanner/bypass_scanner.py
```

Hoac JSON:

```bash
python3 scripts/scanner/bypass_scanner.py --json
```

### Chay audit live rules

```bash
python3 scripts/scanner/firewall_audit.py
```

Hoac JSON:

```bash
python3 scripts/scanner/firewall_audit.py --json
```

### Chay comparison du 3 mode

```bash
python3 scripts/scanner/compare_rules.py
```

### Xoa lab

```bash
bash scripts/labsetup/setup.sh down
```

## 9. Flow demo de xai tren lop

### Demo ngan 3-5 phut

Muc tieu:

- cho thay bypass ton tai
- cho thay fix stateful loai bo bypass

Lenh:

```bash
bash scripts/labsetup/setup.sh up
bash scripts/labsetup/setup.sh mode flawed
python3 scripts/scanner/bypass_scanner.py
python3 scripts/scanner/firewall_audit.py
bash scripts/labsetup/setup.sh mode secure
python3 scripts/scanner/bypass_scanner.py
python3 scripts/scanner/firewall_audit.py
```

Ban nen noi:

1. lab gom attacker, firewall, victim
2. `flawed` cho phep source-port bypass
3. scanner tim thay 4 hidden services
4. audit chi ra rule sai
5. switch sang `secure`
6. scanner khong con hidden service nao
7. audit ve `0 findings`

### Demo day du

Neu muon demo du ca 3 mode:

```bash
bash scripts/labsetup/setup.sh up
bash scripts/labsetup/setup.sh mode flawed
python3 scripts/scanner/bypass_scanner.py
bash scripts/labsetup/setup.sh mode flags
python3 scripts/scanner/bypass_scanner.py
bash scripts/labsetup/setup.sh mode secure
python3 scripts/scanner/bypass_scanner.py
python3 scripts/scanner/compare_rules.py
python3 scripts/scanner/firewall_audit.py
```

Y nghia:

- `flawed`: TCP + UDP hidden service deu lo
- `flags`: TCP duoc giam, UDP van lo
- `secure`: khong con bypass

## 10. Cach doc ket qua scanner nhanh

Neu scanner in:

```text
Public services       : 2
Affected services     : 4
Closed services       : 0
Observable expansion  : 200.0%
```

thi doc nhu sau:

- `public=2`: 2 service dung la public (`80/tcp`, `53/udp`)
- `affected=4`: 4 service dang le hidden nhung bi lo do rule sai
- `closed=0`: trong run do, khong service nao trong target set bi unreachable
- `expansion=200%`: tu 2 service public ban nhin thay them 4 service hidden

Neu dong service ghi:

```text
ssh 22/tcp -> affected
```

thi nghia la:

- designated source port vao duoc
- high-port thong thuong khong vao duoc
- service do dang bi firewall expose sai

Neu ghi:

```text
http 80/tcp -> public
```

thi service do dung la public, khong phai hidden service bi lo.

## 11. Ket qua measured hien tai

Theo report measured gan nhat trong `scripts/results/comparison_results.json`:

- `flawed`
  - `public=2`
  - `affected=4`
- `flags`
  - `public=2`
  - `affected=1`
- `secure`
  - `public=2`
  - `affected=0`

Theo live audit gan nhat trong `scripts/results/audit_results.json`:

- `secure` mode hien tai co `0 findings`

## 12. Luu y khi demo

- `scan_results.json` luon la ket qua cua lan scanner gan nhat, khong phai lich su
- `comparison_results.json` la ket qua du 3 mode cua lan compare gan nhat
- neu muon demo bypass ngay, nho chuyen ve `flawed`
- neu thay ket qua la `secure` ma scanner khong tim ra hidden service nao, day la dung
- script scanner va audit can Docker access, vi chung doc hoac chay ben trong container

## 13. Lenh goi y de dung nhanh

Dung lab:

```bash
bash scripts/labsetup/setup.sh up
```

Demo bypass:

```bash
bash scripts/labsetup/setup.sh mode flawed
python3 scripts/scanner/bypass_scanner.py
python3 scripts/scanner/firewall_audit.py
```

Demo fix:

```bash
bash scripts/labsetup/setup.sh mode secure
python3 scripts/scanner/bypass_scanner.py
python3 scripts/scanner/firewall_audit.py
```

Report tong hop:

```bash
python3 scripts/scanner/compare_rules.py
```

Don dep:

```bash
bash scripts/labsetup/setup.sh down
```
