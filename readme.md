# p2c loader auth
C++ base for p2c loaders. As of now, only includes user authentication and few features, I may add dll transfer and other stuff soon. Made and tested only on x64.

### features
- dynamically encrypted client-server communication over TCP sockets
- loader version check
- license only login system (with expiration and hwid binding)
- hwid blacklisting system
- easy license management

### todo
- safer pid transfer
- security thread
- secured dll transfer
- more license management features
- add option to add time to all licenses at once
- better server UI
- reset hwid
- fix usage of client's IP
- fix bulk license creation

### setup
1. extract shared.rar
2. setup main values (on beginning of client.cpp and server.cpp)
3. add your application code on the end of client.cpp
4. you may add another communication and stuff, well at this point you are good to go

### disclaimer
This was created as a fun project when I was bored over christmas, some code may be trash, feel free to change as you want. As mentioned in the code, only reason for not using an actual database is that not everyone knows how to work with sql.. Will add it later anyways.

### credits
- https://github.com/Joona70 for hwid grabbing method
- https://github.com/weidai11/cryptopp for encryption
