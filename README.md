# About
- POC End-to-End Encryption chat implemented using X3DH + Double Ratchet

# Run
Requires:
- Go 1.24

1. Start Docker
2. Start Redis and mongoDB
```
docker-compose -f ./docker/docker-compose.yaml up -d
```

3. Start Server
```
go run ./cmd/server/
```

4. Start Client
Initialize the user before entering the recipient’s name (first run only):
```
go run ./cmd/client/ alice
go run ./cmd/client/ bob
```
alice and bob will be generated automatically if they do not already exist.
<img width="1788" height="205" alt="image" src="https://github.com/user-attachments/assets/69845cbb-47af-4b68-9b9f-5de07cb31f21" />

Then enter the recipient’s name in the respective window:
<img width="1791" height="372" alt="image" src="https://github.com/user-attachments/assets/8cbf28d0-e074-4fd8-89cc-1625a9d5034e" />

Both users can now have a conversation with each other:
<img width="1793" height="379" alt="image" src="https://github.com/user-attachments/assets/71595df7-3a2b-4f5a-b649-87df61d82e9f" />

Alice can still send messages to Bob even if he is offline — all messages will be delivered once Bob comes back online.




   
