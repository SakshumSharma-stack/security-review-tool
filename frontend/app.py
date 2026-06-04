import streamlit as st
import requests

st.title("Security Review Tool")

code = st.text_area("Paste your code here", height=300)

if st.button("Scan"):
    if code:
        response = requests.post("http://127.0.0.1:8080/scan", json={"code": code})
        st.json(response.json())
    else:
        st.warning("Please paste some code first")