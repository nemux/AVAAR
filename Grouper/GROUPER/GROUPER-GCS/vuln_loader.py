#!/usr/bin/env python
# -*- coding: UTF-8 -*-
__author__ = "NeMuX"
__copyright__ = "Copyright 2014"
__credits__ = ["NeMuX"]
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "NeMuX"
__email__ = "jaraujo@globalcybersec.com"
__status__ = "Development"

import sys
import csv
import sqlite3

def cargar_vulnerabilidades(file,db='info/vulnerabilidades.db'):

    conn = sqlite3.connect(db)
    c = conn.cursor()

    conn.text_factory = "str"

    # Creamos la tabla

    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilidades
             (id INTEGER PRIMARY KEY AUTOINCREMENT, nessus_id INTEGER, qualys_id TEXT, acunetix_id TEXT,
              nombre_vulnerabilidad TEXT,descripcion TEXT, solucion TEXT, workaround TEXT,
              categoria TEXT, efecto TEXT, prioridad TEXT, cvss TEXT, plataforma TEXT,
              subplataforma TEXT, cve TEXT, referencias TEXT, exploit TEXT, estado TEXT,
              patrones TEXT, revisada NUMERIC, severidad NUMERIC)''')

    cvs_file = open(file)
    reader = csv.reader(cvs_file)

    rownum = 0
    colnum = 0

    for r in reader:
        #ignoramos el encabezado
        if rownum == 0:
            colnum = len(r)
            rownum = rownum + 1

        else:
            #Formamos la cadena del INSERT

            #query = "INSERT INTO vulnerabilidades (nessus_id, qualys_id, acunetix_id, nombre_vulnerabilidad, descripcion, solucion, workaround, " \
            #        "categoria, efecto, prioridad, cvss, plataforma, subplataforma, cve, referencias, exploit, estado, patrones, revisada) " \
            #        "VALUES (" + r[1] + ",\"" + r[3] + "\", \"" + r[4] + "\", \"" + r[6] + "\", \"" + r[7] + "\", \"" + r[8] + "\", \"" + r[9] \
            #        + "\", \"" + r[10] + "\", \"" + r[11] + "\", \"" + r[12] + "\", \"" + r[13] + "\", \"" + r[14] + "\", \"" + r[15] + "\", \"" + \
            #        r[16] + "\", \"" + r[17] + "\", \"" + r[18] + "\", \"" + r[19] + "\", \"" + r[20] + "\", \"" + r[21] + "\")"
            #print(query)
            #c.execute(query)

            #data = (r[1],r[3],r[4],r[6],r[7],r[8],r[9],r[10],r[11],r[12],r[13],r[14],r[15],r[16],r[17],r[18],r[19],r[20],r[21],r[22])
            data = (r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11],r[12],r[13],r[14],r[15],r[16],r[17],r[18],r[19])
            #print(str(data) + "\n")
            c.execute('''INSERT INTO vulnerabilidades (nessus_id, qualys_id, acunetix_id, nombre_vulnerabilidad, descripcion, solucion, workaround,
            categoria, efecto, prioridad, cvss, plataforma, subplataforma, cve, referencias, exploit, estado, patrones, revisada, severidad)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',data)
            rownum = rownum + 1
    conn.commit()
    c.close()
    conn.close()
    print(str(rownum-1) + " Registros insertados...")

if __name__ == "__main__":
    if len(sys.argv)  > 1 :
        print("Procesando " + str(len(sys.argv) -1) + " archivos")
        for file in sys.argv[1:]:
            print("Cargando archivo -> " + file)
            cargar_vulnerabilidades(file)
        print("Hecho.")
    else:
        print(sys.argv[0] + ": falta un archivo como argumento" )
