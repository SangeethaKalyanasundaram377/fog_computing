from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import mysql.connector
from mysql.connector import Error
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
import boto3  # AWS SDK for Python to interact with S3
from flask import send_file 
from botocore.exceptions import NoCredentialsError

app = Flask(__name__)
app.secret_key =   # Replace with a strong secret key for session management

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def create_connection():
    try:
        connection = mysql.connector.connect(
            host=
            user=  # Update with your MySQL username
            password= # Update with your MySQL password
            database=  # Update with your database name
        )
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
        return None
    # S3 Client Setup
s3_client = boto3.client(
    's3',
    aws_access_key_id=,  # Replace with your AWS Access Key
    aws_secret_access_key=  # Replace with your AWS Secret Key
    region_name='  # Replace with the AWS region of your S3 bucket
)


@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if request.method == "POST":
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        mobile = data.get("mobile")
        address = data.get("address")
        dob = data.get("dob")
        gender = data.get("gender")

        connection = create_connection()
        if connection is None:
            return jsonify({"success": False, "message": "Database connection failed"})

        try:
            cursor = connection.cursor()
            query_check = "SELECT * FROM login2 WHERE username = %s"
            cursor.execute(query_check, (username,))
            if cursor.fetchone():
                return jsonify({"success": False, "message": "Username already exists"})
            
            query_insert = """
            INSERT INTO login2 (username, password, email, mobile, address, dob, gender) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query_insert, (username, password, email, mobile, address, dob, gender))
            connection.commit()
            return jsonify({"success": True, "message": "Registration successful"})
        except Error as e:
            return jsonify({"success": False, "message": str(e)})
        finally:
            if connection:
                connection.close()
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        data = request.get_json()
        username, password = data.get("username"), data.get("password")
        
        connection = create_connection()
        if connection is None:
            return jsonify({"success": False, "message": "Database connection failed"})

        try:
            cursor = connection.cursor()
            query = "SELECT * FROM login2 WHERE username = %s AND password = %s"
            cursor.execute(query, (username, password))
            
            result = cursor.fetchone()
            if result:
                session['logged_in'] = True
                session['username'] = username
                return jsonify({"success": True, "message": "Login successful", "redirect": url_for('main')})
            else:
                return jsonify({"success": False, "message": "Invalid credentials"})
        except Error as e:
            return jsonify({"success": False, "message": str(e)})
        finally:
            if connection:
                connection.close()
    return render_template("login.html")

@app.route("/main")
def main():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))  # Redirect to login if not logged in
    return render_template("main.html", username=session.get('username'))

@app.route("/fog_login", methods=["GET", "POST"])
def fog_login():
    if request.method == "POST":
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        connection = create_connection()
        if connection is None:
            return jsonify({"success": False, "message": "Database connection failed"})

        try:
            cursor = connection.cursor()
            query = "SELECT * FROM fog_node_login WHERE username = %s AND password = %s"
            cursor.execute(query, (username, password))
            
            result = cursor.fetchone()
            if result:
                # Successful login
                session['fog_logged_in'] = True
                session['fog_username'] = username
                return jsonify({"success": True, "redirect": url_for('fog_node')})
            else:
                # Invalid credentials
                return jsonify({"success": False, "message": "Invalid credentials"})
        except Error as e:
            return jsonify({"success": False, "message": str(e)})
        finally:
            if connection:
                connection.close()

    return render_template("fog_login.html")


@app.route("/fog_node")
def fog_node():
    if not session.get('fog_logged_in'):
        return redirect(url_for('fog_login'))

    connection = create_connection()
    if connection is None:
        return jsonify({"success": False, "message": "Database connection failed"})

    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM file WHERE uploaded_by = %s"
        cursor.execute(query, (session['fog_username'],))
        files = cursor.fetchall()
        return render_template("fog_node.html", files=files)  # Pass files to the template
    except Error as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        if connection:
            connection.close()

@app.route("/view")
def view_profile():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))

    username = session.get('username')  # Get the logged-in username

    connection = create_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cursor = connection.cursor()
        query = "SELECT * FROM login2 WHERE username = %s"
        cursor.execute(query, (username,))
        user_data = cursor.fetchone()
        
        if user_data:
            user_dict = {
                "username": user_data[1],
                "email": user_data[2],
                "address": user_data[3],
                "mobile": user_data[4],
                "dob": user_data[5],
                "gender": user_data[6]
            }
            return jsonify(user_dict)
        else:
            return jsonify({"error": "User not found"}), 404
    except Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if connection:
            connection.close()

@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))

    if request.method == "POST":
        file_id = request.form['file_id']
        uploaded_by = session['username']  # Use the logged-in username
        file_name = request.form['file_name']
        file = request.files['file']

        if file:
            file_data = file.read()

            # Generate ECC key pair
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()

            # Derive shared key using ECDH
            shared_key = private_key.exchange(ec.ECDH(), public_key)

            # Derive AES key from shared key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'file_encryption',
                backend=default_backend()
            ).derive(shared_key)

            # Encrypt the file data using AES-GCM
            iv = os.urandom(12)  # 12 bytes IV for AES-GCM
            encryptor = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()
            ciphertext = encryptor.update(file_data) + encryptor.finalize()

            connection = create_connection()
            if connection is None:
                return jsonify({"success": False, "message": "Database connection failed"})
            
            try:
                cursor = connection.cursor()
                query_insert = """
                INSERT INTO file (file_id, uploaded_by, file_name, file_data, encryption_key) 
                VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(query_insert, (
                    file_id,
                    uploaded_by,
                    file_name,
                    base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8'),
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                ))
                connection.commit()
                return jsonify({"success": True, "message": "File uploaded successfully"})
            except Error as e:
                return jsonify({"success": False, "message": str(e)})
            finally:
                if connection:
                    connection.close()

    return render_template("uploadedfiles.html")

@app.route("/uploadedfiles", methods=["GET"])
def uploaded_files():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))

    connection = create_connection()
    if connection is None:
        return jsonify({"success": False, "message": "Database connection failed"})

    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM file"
        cursor.execute(query)
        files = cursor.fetchall()
        return render_template("uploadedfiles.html", files=files)  # Pass files to the template
    except Error as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        if connection:
            connection.close()

@app.route("/encrypt_to_cloud", methods=["POST"])
def encrypt_to_cloud():
    data = request.get_json()
    file_id = data.get("file_id")

    connection = create_connection()
    if connection is None:
        return jsonify({"success": False, "message": "Database connection failed"})

    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT file_data FROM file WHERE file_id = %s"
        cursor.execute(query, (file_id,))
        file_record = cursor.fetchone()

        if not file_record:
            return jsonify({"success": False, "message": "File not found"})

        file_data = base64.b64decode(file_record["file_data"])

        # Define the S3 upload path (key) for the file
        s3_file_key = f"encrypted_files/{file_id}.enc"

        # Upload the file data to S3
        s3_client.put_object(
            Bucket="myproject2024",
            Key=s3_file_key,
            Body=file_data
        )

        return jsonify({"success": True, "message": "File uploaded to cloud successfully"})
    except NoCredentialsError:
        return jsonify({"success": False, "message": "AWS credentials not available"})
    except Error as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        if connection:
            connection.close()

@app.route("/download_encrypted/<file_id>", methods=["GET"])
def download_encrypted(file_id):
    # Create S3 client
    s3 = boto3.client('s3')
    bucket_name = 'myproject2024'  # Your S3 bucket name

    # Fetch file metadata from the database
    connection = create_connection()
    if connection is None:
        return jsonify({"success": False, "message": "Database connection failed"})

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM file WHERE file_id = %s", (file_id,))
        file_record = cursor.fetchone()

        if not file_record:
            return jsonify({"success": False, "message": "File not found"})

        # Assuming you have the file name in your database record
        s3_file_key = file_record["file_key"]  # The key used to store the file in S3

        # Download the file from S3 to a temporary location
        local_file_path = os.path.join('downloadedfiles', file_record["file_name"])
        s3.download_file(bucket_name, s3_file_key, local_file_path)

        # Return the file for download
        return send_file(local_file_path, as_attachment=True)

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        if connection:
            connection.close()
         



# Function to get the private key from the database
def get_private_key_from_db(file_id):
    try:
        connection = mysql.connector.connect(
            host="",
            user="",
            password="",
            database=" "
        )
        cursor = connection.cursor(dictionary=True)
        # Adjust query to fit your database schema
        query = "SELECT private_key FROM private WHERE file_id = %s"
        cursor.execute(query, (file_id,))
        result = cursor.fetchone()
        return result['private_key'] if result else None
    except mysql.connector.Error as err:
        print("Database error:", err)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return None

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    data = request.json
    file_id = data.get('file_id')
    entered_key = data.get('private_key')

    stored_private_key = get_private_key_from_db(file_id)

    if not stored_private_key:
        return jsonify({"success": False, "message": "File not found or unauthorized access."})

    if entered_key != stored_private_key:
        return jsonify({"success": False, "message": "Incorrect private key. Unauthorized access detected."})

    # Proceed with decryption if keys match (implement ECC decryption here)
    try:
        # ECC decryption logic
        decrypted_data = "Your decrypted data here"  # Replace with actual decrypted content

        # Save or return the decrypted data as needed
        return jsonify({"success": True, "message": "File decrypted successfully.", "data": decrypted_data})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/logout")
def logout():
    session.clear()  # Clear session data
    return redirect(url_for('welcome'))

if __name__ == "__main__":
    app.run(debug=True,host='127.0.0.1', port=5000)  # No SSL context specified here
