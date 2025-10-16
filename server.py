import random
import socket
import pickle
import threading
import time

lamda = 84  
m = 1024
n = euler_phi(m)    #deg(f)
f = cyclotomic_polynomial(m)
R.<x> = PolynomialRing(ZZ)  
Rq = QuotientRing(R, f)     #ℤ[x]/(f(x))
q = 12289     #prime, small and noise
Zq = Integers(q)
Rq_mod = QuotientRing(PolynomialRing(Zq, 'x'), f) # implemetation of Rq in code 


k = 3
B = [Rq_mod.random_element() for _ in range(k)]
a_star = Rq_mod.random_element()
standard_key_generation_parameters = (a_star, B)



def sample_error():
    # small noise distribution from -3 to 3
    # ei
    coeffs = [random.randint(-3, 3) for _ in range(n)]
    return Rq_mod(R(coeffs))




e_list = [sample_error() for _ in range(k)] # server sends e_list to all users


ALLOWED_CLIENTS = {"127.0.0.1", "192.168.1.5"}  # list of all clients to broadcast to



def send_data(conn, obj):
    data = pickle.dumps(obj)
    conn.sendall(len(data).to_bytes(4, "big") + data)


def recv_data(conn):
    length_bytes = conn.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, "big")
    data = b""
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return pickle.loads(data)


def broadcast(obj, store_dict):
    """Send obj (list) to all connected clients"""
    for sock in client_sockets.values():
        send_data(sock, obj)





HOST = "0.0.0.0" 
PORT = 65432

client_sockets = {}
public_keys = {}
partial_decryption_keys = {}
R1_list = {}
R2_list= {}

lock = threading.Lock()

def handle_client(conn, addr, client_id):
    global public_keys, partial_decryption_keys, R1_list, R2_list


    # send initial params and e_list
    send_data(conn, standard_key_generation_parameters)
    send_data(conn, e_list)
    print(f"Sent params+e_list to {client_id}")




    # receive pk_i from all clients
    # server gets all public keys from all the users, combines and sends list of combined public keys to all the users

    pk_i = recv_data(conn)
    with lock:
        public_keys[client_id] = pk_i
        print(f"Received pk_i from {client_id}")
        # braodcast only after all are received
        if len(public_keys) == len(ALLOWED_CLIENTS):
            broadcast(list(public_keys.values()), public_keys)




    # each user sends its pdkj corresponding to a ct to server
    # server collects all pdkjs corresponding to a ct and sends it to all users 

    pdkj = recv_data(conn)
    with lock:
        partial_decryption_keys[client_id] = pdkj
        print(f"Received pdkj from {client_id}")
        if len(partial_decryption_keys) == len(ALLOWED_CLIENTS):
            broadcast(list(partial_decryption_keys.values()), partial_decryption_keys)


    # after collection all R1,s from all users, server sends R1_list to all users
    r1 = recv_data(conn)
    with lock:
        R1_list[client_id] = r1
        print(f"Received R1 from {client_id}")
        if len(R1_list) == len(ALLOWED_CLIENTS):
            broadcast(list(R1_list.values()), R1_list)
    


    # after collecting all R2's from all users, server sends R2_list to all users
    r2 = recv_data(conn)
    with lock:
        R2_list[client_id] = r2
        print(f"Received R2 from {client_id}")
        if len(R2_list) == len(ALLOWED_CLIENTS):
            broadcast(list(R2_list.values()), R2_list)





with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        client_ip = addr[0]
        if client_ip not in ALLOWED_CLIENTS:
            print(f"Rejected {client_ip}")
            conn.close()
            continue

        print(f"Accepted connection from {client_ip}")
        client_sockets[client_ip] = conn
        threading.Thread(target=handle_client, args=(conn, addr, client_ip), daemon=True).start()




