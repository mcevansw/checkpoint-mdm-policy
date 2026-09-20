domain: Domain001

policy_package: Standard

hosts:
  - name: WEB01
    ip: 10.10.10.20

networks:
  - name: NET_LAN
    subnet: 10.10.10.0
    mask: 255.255.255.0

rules:
  - name: Allow-HTTPS
    source:
      - NET_LAN
    destination:
      - WEB01
    service:
      - https
    action: Accept