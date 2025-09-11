import time
import os
import uuid
from datetime import datetime

import streamlit as st
import bcrypt

from utility import database_connection as db
from frontend_utility import ui

# =========================
# Config pagina + stile
# =========================
st.set_page_config(page_title="Settings", layout="wide", initial_sidebar_state="collapsed")
ui.load_css()

# =========================
# Auth gate
# =========================
if "logged_in" not in st.session_state or not st.session_state["logged_in"]:
    st.warning("Effettua il login per accedere.")
    st.stop()

user_id = st.session_state["user_id"]

# === Info utente (username, email, name, surname) ===
def get_user_info(user_id):
    conn = db.connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username, u.email, COALESCE(up.name, ''), COALESCE(up.surname, '')
        FROM users u
        LEFT JOIN users_profile up ON u.user_id = up.user_id
        WHERE u.user_id = %s
    """, (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row if row else ("", "", "", "")

# === Hash password attuale ===
def get_password_hash(user_id):
    conn = db.connection()
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE user_id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None

# === Utility: esiste profilo? ===
def profile_exists(user_id):
    conn = db.connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users_profile WHERE user_id = %s", (user_id,))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists

# === Aggiorna SOLO username ===
def update_username(user_id, new_username):
    conn = db.connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users SET username = %s
            WHERE user_id = %s
        """, (new_username, user_id))
        conn.commit()
        st.success("Username aggiornato con successo.")
    except Exception as e:
        conn.rollback()
        st.error(f"Errore durante l'aggiornamento dell'username: {e}")
    finally:
        cur.close()
        conn.close()

# === Aggiorna SOLO nome ===
def update_name(user_id, new_name):
    conn = db.connection()
    cur = conn.cursor()
    try:
        if profile_exists(user_id):
            cur.execute("""
                UPDATE users_profile
                SET name = %s, updated_at = NOW()
                WHERE user_id = %s
            """, (new_name, user_id))
        else:
            cur.execute("""
                INSERT INTO users_profile (user_id, name, surname)
                VALUES (%s, %s, %s)
            """, (user_id, new_name, ""))  # se non esiste, inizializza surname vuoto
        conn.commit()
        st.success("Nome aggiornato con successo.")
    except Exception as e:
        conn.rollback()
        st.error(f"Errore durante l'aggiornamento del nome: {e}")
    finally:
        cur.close()
        conn.close()

# === Aggiorna SOLO cognome ===
def update_surname(user_id, new_surname):
    conn = db.connection()
    cur = conn.cursor()
    try:
        if profile_exists(user_id):
            cur.execute("""
                UPDATE users_profile
                SET surname = %s, updated_at = NOW()
                WHERE user_id = %s
            """, (new_surname, user_id))
        else:
            cur.execute("""
                INSERT INTO users_profile (user_id, name, surname)
                VALUES (%s, %s, %s)
            """, (user_id, "", new_surname))  # se non esiste, inizializza name vuoto
        conn.commit()
        st.success("Cognome aggiornato con successo.")
    except Exception as e:
        conn.rollback()
        st.error(f"Errore durante l'aggiornamento del cognome: {e}")
    finally:
        cur.close()
        conn.close()

# === Aggiorna SOLO password (con verifica vecchia) ===
def update_password(user_id, old_password, new_password):
    current_hash = get_password_hash(user_id)
    if not current_hash:
        st.error("Impossibile recuperare la password attuale.")
        return

    # current_hash potrebbe essere str o bytes a seconda del driver
    current_hash_bytes = current_hash.encode('utf-8') if isinstance(current_hash, str) else current_hash

    if not bcrypt.checkpw(old_password.encode('utf-8'), current_hash_bytes):
        st.error("La vecchia password non è corretta.")
        return

    new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    new_hashed_str = new_hashed.decode('utf-8')

    conn = db.connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users SET password = %s
            WHERE user_id = %s
        """, (new_hashed_str, user_id))
        conn.commit()
        st.success("Password aggiornata con successo.")
    except Exception as e:
        conn.rollback()
        st.error(f"Errore durante l'aggiornamento della password: {e}")
    finally:
        cur.close()
        conn.close()

# =========================
# Layout colonne (convenzione di progetto)
# =========================
sidebar_col, main_col = st.columns([0.8, 6.2], gap="large")

with sidebar_col:
    # Mostriamo il nome attuale (se presente)
    _, _, current_name, current_surname = get_user_info(user_id)
    ui.render_sidebar(current_name, current_surname, user_id)

with main_col:
    # Header comune
    ui.render_header("Settings", "Gestisci profilo, password e dispositivo")

    st.subheader("Profilo Utente")
    username, email, name, surname = get_user_info(user_id)

    # === Sezioni separate ===
    col_a, col_b = st.columns(2)

    # --- Sezione: Cambia Username ---
    with col_a:
        with st.form("form_update_username", clear_on_submit=False):
            st.markdown("#### Cambia username")
            new_username = st.text_input("Nuovo username", value=username, key="username_input")
            submitted_user = st.form_submit_button("Aggiorna username")
            if submitted_user:
                if not new_username:
                    st.warning("L'username non può essere vuoto.")
                else:
                    update_username(user_id, new_username)
                    st.rerun()

    # --- Sezione: Cambia Password ---
    with col_b:
        with st.form("form_update_password", clear_on_submit=True):
            st.markdown("#### Cambia password")
            old_password = st.text_input("Vecchia password", type="password")
            new_password = st.text_input("Nuova password", type="password")
            submitted_pwd = st.form_submit_button("Aggiorna password")
            if submitted_pwd:
                if not old_password or not new_password:
                    st.warning("Compila sia la vecchia che la nuova password.")
                elif len(new_password) < 8:
                    st.warning("La nuova password deve avere almeno 8 caratteri.")
                else:
                    update_password(user_id, old_password, new_password)

    col_c, col_d = st.columns(2)

    # --- Sezione: Cambia Nome ---
    with col_c:
        with st.form("form_update_name", clear_on_submit=False):
            st.markdown("#### Cambia nome")
            new_name = st.text_input("Nuovo nome", value=name, key="name_input")
            submitted_name = st.form_submit_button("Aggiorna nome")
            if submitted_name:
                if not new_name:
                    st.warning("Il nome non può essere vuoto.")
                else:
                    update_name(user_id, new_name)
                    st.rerun()

    # --- Sezione: Cambia Cognome ---
    with col_d:
        with st.form("form_update_surname", clear_on_submit=False):
            st.markdown("#### Cambia cognome")
            new_surname = st.text_input("Nuovo cognome", value=surname, key="surname_input")
            submitted_surname = st.form_submit_button("Aggiorna cognome")
            if submitted_surname:
                if not new_surname:
                    st.warning("Il cognome non può essere vuoto.")
                else:
                    update_surname(user_id, new_surname)
                    st.rerun()

    # --- Dati non modificabili qui (email in sola lettura, se vuoi mantenerla visibile) ---
    with st.expander("Altre informazioni"):
        st.markdown(f"**Email (sola lettura):** {email}")

    # Logout
    st.divider()
    if st.button("Log out"):
        if "user_id" in st.session_state:
            del st.session_state["user_id"]
        st.success("Logout effettuato.")
        time.sleep(1)
        st.switch_page("app.py")
        st.rerun()

    st.divider()

    # --- Gestione dispositivi e sensori ---
    st.subheader("🔧 Gestione dispositivi e sensori")
    st.caption("Accedi alla pagina dove puoi rinominare, eliminare o aggiungere dispositivi e sensori.")

    col1, col2 = st.columns([1, 3])
    with col1:
        try:
            st.page_link("pages/manage_bindings.py", label="Vai alla gestione", icon="🔗")
        except Exception:
            if st.button("Apri gestione"):
                st.switch_page("pages/manage_bindings.py")
    with col2:
        st.caption("Puoi modificare i nomi dei dispositivi e dei sensori o rimuoverli definitivamente.")
