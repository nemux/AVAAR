#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
Reporter.reporformat
~~~~~~~~~~~~~

A description which can be long and explain the complete
functionality of this module even with indented code examples.
Class/Function however should not be documented here.

:copyright: 2014 by NeMuX, see AUTHORS for more details
:license: Apache 2.0, see LICENSE for more details
"""

__author__ = "NeMuX"
__copyright__ = "Copyright 2014"
__credits__ = ["NeMuX"]
__license__ = "Apache 2.0"
__version__ = "0.1"
__maintainer__ = "NeMuX"
__email__ = "jaraujo@globalcybersec.com"
__status__ = "Development"

from odf.opendocument import *
from odf.style import *
from odf.text import *
from odf.table import *
from odf.draw import Frame, Image

from gcs.utils import *
from gcs.reportgraphics import *

def crear_tabla_reporte(reporte,data):

    #Ponemos el titulo de la vulnerabilidad a reportar
    #vulnerabilidad,ip,servicio,impacto,descripcion,solucion

    tit = P(stylename="Seccion Title 10",text=unicode_string(data["Nombre_de_Vulnerabilidad"]))
    reporte.text.addElement(tit)

    #Creamos la tabla de reporte de vulnerabilidad
    vuln_table = Table(stylename="Table.Vuln")

    vuln_table.addElement(TableColumn(stylename="TCVShort-0450"))
    vuln_table.addElement(TableColumn(stylename="TCVLong-1300"))

    tr_vuln = TableRow()
    vuln_table.addElement(tr_vuln)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text=unicode_string("Dirección IP"))
    tc.addElement(p)

    tc = TableCell(stylename="Table.Vuln.Body.Cell.Just")
    tr_vuln.addElement(tc)
    for i in data["ip_list"]:
        p = P(stylename="Table Vuln Body Bold Left", text=unicode_string(i))
        tc.addElement(p)

    tr_vuln = TableRow()
    vuln_table.addElement(tr_vuln)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Puerto")
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Just")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Body Left", text=unicode_string(data["Servicio"]))
    tc.addElement(p)

    tr_vuln = TableRow()
    vuln_table.addElement(tr_vuln)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Impacto / CVSS")
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Just")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Body Left", text=unicode_string(data["CVSS"]))
    tc.addElement(p)

    tr_vuln = TableRow()
    vuln_table.addElement(tr_vuln)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text=unicode_string("Descripción"))
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Just")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Body Left", text=unicode_string(data["Descripcion"]))
    tc.addElement(p)

    tr_vuln = TableRow()
    vuln_table.addElement(tr_vuln)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text=unicode_string("Recomendación"))
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Just")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Body Left", text=unicode_string(data["Solucion"]))
    tc.addElement(p)


    tr_vuln = TableRow()
    vuln_table.addElement(tr_vuln)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Referencias")
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Just")
    tr_vuln.addElement(tc)
    p = P(stylename="Table Vuln Body Left", text=unicode_string(data["Referencias"]))
    tc.addElement(p)


    #TERMINA Creamos la tabla de la descripcion de la vulnerabilidad

    reporte.text.addElement(P(text="\n"))
    reporte.text.addElement(vuln_table)
    reporte.text.addElement(P(text="\n\n"))
    return reporte

    ##########################################


def crear_tabla_ip_hostname(reporte,titulo_tabla,ip_hostname_list):


    reporte.text.addElement(P(stylename="Seccion Title 10",text=titulo_tabla))

    tabla_ips = Table(stylename="Table.IP")
    tabla_ips.addElement(TableColumn(stylename="TCVShort-0450"))
    tabla_ips.addElement(TableColumn(stylename="TCVShort-0450"))

    #Creamos el encabezado

    fila = TableRow()
    tabla_ips.addElement(fila)
    tc = TableCell(stylename="Table.Ip.Header.Cell")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text=unicode_string("Dirección IP"))
    tc.addElement(p)

    tc = TableCell(stylename="Table.Ip.Header.Cell")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Nombre")
    tc.addElement(p)

    #Llenamos la tabla con la informacion de IP Hostname

    for ip,hostname in ip_hostname_list:
        fila = TableRow()
        tabla_ips.addElement(fila)
        tc = TableCell(stylename="Table.Ip.Body.Cell.Just")
        fila.addElement(tc)
        p = P(stylename="Table Vuln Body Left",text=ip)
        tc.addElement(p)
        tc = TableCell(stylename="Table.Ip.Body.Cell.Just")
        fila.addElement(tc)
        p = P(stylename="Table Vuln Body Left",text=hostname)
        tc.addElement(p)

    reporte.text.addElement(tabla_ips)
    reporte.text.addElement(P(text="\n\n"))

def crear_tabla_vulnerabilidades(reporte,titulo_tabla,vuln_list, prioridad):

    severidad = prioridad

    reporte.text.addElement(P(stylename="Seccion Title 10",text=titulo_tabla))
    tabla_ips = Table(stylename="Table")
    tabla_ips.addElement(TableColumn(stylename="Table.Column"))
    tabla_ips.addElement(TableColumn(stylename="Table.Column"))

    #Creamos el encabezado

    fila = TableRow()
    tabla_ips.addElement(fila)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Vulnerabilidad")
    tc.addElement(p)

    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Criticidad")
    tc.addElement(p)

    #Llenamos la tabla con la informacion de IP Hostname
    for vuln_name in vuln_list:
        fila = TableRow()
        tabla_ips.addElement(fila)
        tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
        fila.addElement(tc)
        p = P(stylename="Table Vuln Body Left",text=unicode_string(vuln_name))
        tc.addElement(p)
        tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
        fila.addElement(tc)

        severidad_text = ""

        if severidad <=1:
            severidad_text = "BAJA"
        if severidad == 2:
            severidad_text = "MEDIA"
        if severidad >= 3:
            severidad_text = "ALTA"

        p = P(stylename="Table Vuln Body Left",text=severidad_text)
        tc.addElement(p)

    reporte.text.addElement(tabla_ips)
    reporte.text.addElement(P(text="\n\n"))
    return reporte

def crear_texto_generico(reporte):

    #Agregamos el objetivo del documento
    texto = leer_archivo_texto("template/informacion_general.apl")
    crear_seccion_texto(reporte,u"1. Informaci\u00f3n general",texto)

    #Agregamos la introduccion
    texto = leer_archivo_texto("template/objetivo.apl")
    crear_seccion_texto(reporte,u"2. Objetivo",texto)

    #Agregamos el alcance
    texto = leer_archivo_texto("template/alcance.apl")
    crear_seccion_texto(reporte,"3. Alcance",texto)

    #Agregamos las definiciones
    texto = leer_archivo_texto("template/resumen_ejecutivo.apl")
    crear_seccion_texto(reporte,"4. Resumen Ejecutivo",texto)

    texto = leer_archivo_texto("template/definiciones.apl")
    crear_seccion_texto(reporte,u"5. Definiciones",texto)

    #Agregamos las Vision General
    texto = leer_archivo_texto("template/vision_general.apl")
    crear_seccion_texto(reporte,u"6. Visi\u00f3n General",texto)

    #Agregamos las Vision General
    texto = leer_archivo_texto("template/actividades_realizadas.apl")
    crear_seccion_texto(reporte,u"7. Descripci\u00f3n de Actividades Realizadas",texto)

    texto = leer_archivo_texto("template/matriz_criticidad.apl")
    crear_seccion_texto(reporte,u"8.Matriz de Criticidad",texto)


def totales_por_tabla(reporte, totales):

    tabla_totales = Table(stylename="Table")

    tabla_totales.addElement(TableColumn(stylename="Table.Column"))
    tabla_totales.addElement(TableColumn())

    #Agregamos los encabezados
    fila = TableRow()
    tabla_totales.addElement(fila)
    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Riesgo")
    tc.addElement(p)

    tc = TableCell(stylename="Table.Vuln.Header.Cell")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Header Center",text="Ocurrencias")
    tc.addElement(p)

    #Llenamos la tabla con el total de ocurrencias

    fila = TableRow()
    tabla_totales.addElement(fila)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Body Left",text="Altas")
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Body Left",text=totales["Altas"])
    tc.addElement(p)

    fila = TableRow()
    tabla_totales.addElement(fila)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Body Left",text="Medias")
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Body Left",text=totales["Medias"])
    tc.addElement(p)

    fila = TableRow()
    tabla_totales.addElement(fila)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Body Left",text="Bajas")
    tc.addElement(p)
    tc = TableCell(stylename="Table.Vuln.Body.Cell.Left")
    fila.addElement(tc)
    p = P(stylename="Table Vuln Body Left",text=totales["Bajas"])
    tc.addElement(p)

    reporte.text.addElement(tabla_totales)
    return reporte

def crear_seccion_texto(reporte,titulo,texto):

    p = P(text=titulo, stylename="Seccion Title 12")
    reporte.text.addElement(p)
    reporte.text.addElement(P(text="\n"))

    for t in texto:
        p = P(text=t,stylename="Seccion Body")
        reporte.text.addElement(p)

    reporte.text.addElement(P(text="\n\n"))
    return reporte

def leer_archivo_texto(archivo):
    text=[]
    f = open(archivo,"r")
    for line in f:
        text.append(unicode_string(line))
    return text


def crear_reporte_odt():
    #Creamos el documento
    reporte = OpenDocumentText()

    '''
        Para agregar un tipo de fuente o cambio al estilo, primero hay que crear las propiedades que se le aplicaran, despues crear el estilo y por ultimo agregar
        las propiedades creadas al estilo.

        El uso se hace cuando se crea un elemento y se aplica con la propiedad stylename
    '''

    ###Definimos los estilos del reporte

    ##Titulo de tamanio 12
    seccion_title_text_prop_12 = TextProperties(attributes={'fontsize':"12pt",'fontweight':"bold", "fontfamily":"Arial" })
    seccion_title_style_12 = Style(name="Seccion Title 12", family="paragraph")
    seccion_title_style_12.addElement(seccion_title_text_prop_12)

    ##Texto para los parrafos
    seccion_title_text_prop_10 = TextProperties(attributes={'fontsize':"10pt",'fontweight':"bold", "fontfamily":"Arial" })
    seccion_title_style_10 = Style(name="Seccion Title 10", family="paragraph")
    seccion_title_style_10.addElement(seccion_title_text_prop_10)

    ##Texto centrado usado en el titulo de la tabla de vulnerabilidades
    table_title_vuln_center_text_props = TextProperties(attributes={'fontsize':"10pt",'fontweight':"bold", "color":"#FFFFFF", "fontfamily":"Arial"})
    table_title_vuln_center_parag_props = ParagraphProperties(textalign="center")
    table_title_vuln_center_style = Style(name="Table Vuln Header Center", family="paragraph")
    table_title_vuln_center_style.addElement(table_title_vuln_center_text_props)
    table_title_vuln_center_style.addElement(table_title_vuln_center_parag_props)

    ##Texto a la izquierda usado en el titulo de la tabla de vulnerabilidades
    table_title_vuln_left_text_props = TextProperties(attributes={'fontsize':"10pt",'fontweight':"bold", "color":"#FFFFFF", "fontfamily":"Arial" })
    table_title_vuln_left_parag_props = ParagraphProperties(textalign="left")
    table_title_vuln_left_style = Style(name="Table Vuln Header Left", family="paragraph")
    table_title_vuln_left_style.addElement(table_title_vuln_left_text_props)
    table_title_vuln_left_style.addElement(table_title_vuln_left_parag_props)

    ##Texto usado en el cuerpo del documento
    text_seccion_body_prop = TextProperties(attributes={'fontsize':"10pt", "fontfamily":"Arial" })
    seccion_body_style = Style(name="Seccion Body", family="paragraph")
    seccion_body_style.addElement(text_seccion_body_prop)

    ##Texto centrado usado en el cuerpo de la tabla de vunerabilidades
    table_body_vuln_center_text_prop = TextProperties(attributes={'fontsize':"10pt", "fontfamily":"Arial" })
    table_body_vuln_center_parag_prop = ParagraphProperties(textalign="center",verticalalign="middle")
    table_body_vuln_center_style = Style(name="Table Vuln Body Center", family="paragraph")
    table_body_vuln_center_style.addElement(table_body_vuln_center_text_prop)
    table_body_vuln_center_style.addElement(table_body_vuln_center_parag_prop)

    ##Texto a la izquierda usado en el cuerpo de la tabla de vulnerabilidades
    table_body_vuln_left_text_prop = TextProperties(attributes={'fontsize':"10pt", "fontfamily":"Arial" })
    table_body_vuln_left_parag_prop = ParagraphProperties(textalign="left",verticalalign="middle")
    table_body_vuln_left_style = Style(name="Table Vuln Body Left", family="paragraph")
    table_body_vuln_left_style.addElement(table_body_vuln_left_text_prop)
    table_body_vuln_left_style.addElement(table_body_vuln_left_parag_prop)

    table_body_vuln_left_text_bold_prop = TextProperties(attributes={'fontsize':"10pt", "fontfamily":"Arial", 'fontweight':"bold" })
    table_body_vuln_left_parag_bold_prop = ParagraphProperties(textalign="left",verticalalign="middle")
    table_body_vuln_left_bold_style = Style(name="Table Vuln Body Bold Left", family="paragraph")
    table_body_vuln_left_bold_style.addElement(table_body_vuln_left_text_bold_prop)
    table_body_vuln_left_bold_style.addElement(table_body_vuln_left_parag_bold_prop)

    ##Columna de tamanio 4.50cm
    table_column_vuln_title_prop = TableColumnProperties(columnwidth="4.50cm")
    table_column_vuln_title_style= Style(name="TCVShort-0450", family="table-column")
    table_column_vuln_title_style.addElement(table_column_vuln_title_prop)

    ##Columna de tamanio 13.00cm
    table_column_vuln_body_prop = TableColumnProperties(columnwidth="13cm",)
    table_column_vuln_body_style = Style(name="TCVLong-1300", family="table-column")
    table_column_vuln_body_style.addElement(table_column_vuln_body_prop)

    ##Propiedades generales de la tabla de vulnerabilidades
    table_vuln_prop = TableProperties(width="17.50cm", marginleft="0.050cm", align="left")
    table_vuln_style = Style(name="Table.Vuln",family="table")
    table_vuln_style.addElement(table_vuln_prop)

    ##Propiedades generales de la tabla de IP
    table_ip_prop = TableProperties(width="9cm", marginleft="0.050cm", align="center")
    table_ip_style = Style(name="Table.IP",family="table")
    table_ip_style.addElement(table_ip_prop)

    ###Estilos de las celdas de las tablas
    #Tabla de IP
    '''
    <style:table-cell-properties style:vertical-align="middle" fo:background-color="#001a88" fo:padding="0.049cm" fo:border-left="2pt solid #ffffff"
    fo:border-right="none" fo:border-top="none" fo:border-bottom="2pt solid #ffffff"/>
    '''
    table_ip_header_cell_prop = TableCellProperties(borderleft="2pt solid #ffffff", borderright="none",
                                        bordertop="none", borderbottom="2pt solid #ffffff", padding="0.50cm", backgroundcolor="#001A88", verticalalign="middle")
    table_ip_header_cell_style = Style(name="Table.Ip.Header.Cell",family="table-cell")
    table_ip_header_cell_style.addElement(table_ip_header_cell_prop)

    '''
    <style:table-cell-properties style:vertical-align="middle" fo:background-color="#dddddd" fo:padding="0.049cm" fo:border-left="2pt solid #ffffff"
    fo:border-right="2pt solid #ffffff" fo:border-top="none" fo:border-bottom="2pt solid #ffffff">
    '''
    table_ip_body_cell_just_prop = TableCellProperties(borderleft="2pt solid #ffffff", borderright="2pt solid #ffffff",
                                        bordertop="none", borderbottom="2pt solid #ffffff", padding="0.50cm", backgroundcolor="#dddddd", verticalalign="middle")
    table_ip_body_cell_just_style = Style(name="Table.Ip.Body.Cell.Just",family="table-cell")
    table_ip_body_cell_just_style.addElement(table_ip_body_cell_just_prop)

    #Tabla de Vulnerabilidades
    '''
    <style:table-cell-properties style:vertical-align="middle" fo:background-color="#001a88" fo:padding="0.049cm" fo:border-left="2pt solid #ffffff"
    fo:border-right="none" fo:border-top="none" fo:border-bottom="2pt solid #ffffff"/>
    '''
    table_vuln_header_cell_prop = TableCellProperties(borderleft="2pt solid #ffffff", borderright="none",
                                        bordertop="none", borderbottom="2pt solid #ffffff", padding="0.50cm", backgroundcolor="#001A88", verticalalign="middle")
    table_vuln_header_cell_style = Style(name="Table.Vuln.Header.Cell",family="table-cell")
    table_vuln_header_cell_style.addElement(table_vuln_header_cell_prop)

    '''
    <style:table-cell-properties style:vertical-align="middle" fo:background-color="#dddddd" fo:padding="0.049cm" fo:border-left="2pt solid #ffffff"
    fo:border-right="2pt solid #ffffff" fo:border-top="none" fo:border-bottom="2pt solid #ffffff">
    '''
    table_vuln_body_cell_just_prop = TableCellProperties(borderleft="2pt solid #ffffff", borderright="2pt solid #ffffff",
                                        bordertop="none", borderbottom="2pt solid #ffffff", padding="0.50cm", backgroundcolor="#dddddd", verticalalign="middle")
    table_vuln_body_cell_just_style = Style(name="Table.Vuln.Body.Cell.Just",family="table-cell")
    table_vuln_body_cell_just_style.addElement(table_vuln_body_cell_just_prop)


    reporte.styles.addElement(seccion_title_style_12)
    reporte.styles.addElement(seccion_title_style_10)
    reporte.styles.addElement(table_title_vuln_center_style)
    reporte.styles.addElement(table_title_vuln_left_style)
    reporte.styles.addElement(table_body_vuln_left_bold_style)
    reporte.styles.addElement(seccion_body_style)
    reporte.styles.addElement(table_body_vuln_center_style)
    reporte.styles.addElement(table_body_vuln_left_style)
    reporte.styles.addElement(table_column_vuln_title_style)
    reporte.styles.addElement(table_column_vuln_body_style)
    reporte.automaticstyles.addElement(table_ip_style)

    reporte.automaticstyles.addElement(table_vuln_header_cell_style)
    reporte.automaticstyles.addElement(table_ip_header_cell_style)
    reporte.automaticstyles.addElement(table_ip_body_cell_just_style)
    reporte.automaticstyles.addElement(table_vuln_body_cell_just_style)
    reporte.automaticstyles.addElement(table_column_vuln_title_style)
    reporte.automaticstyles.addElement(table_column_vuln_body_style)
    reporte.automaticstyles.addElement(table_ip_style)
    reporte.automaticstyles.addElement(table_vuln_style)

    return reporte

def guardar_reporte_odf(reporte,nombre):
    reporte.save(nombre,addsuffix=True)

def write_seccion_report_by_priority(reporte, vuln_list, vuln_info):
    #Recorremos la lista de vulnerabilidades para pintarlas en el reporte
    #NessusID[0], Nombre_de_Vulnerabilidad[1], IP[2], Protocolo[3],Puerto[4], Severidad[5], Prioridad[6], Descripcion[7], Solucion[8]
    for v in vuln_list:
        ip_list_by_vuln = []
        report_vuln_data = {}
        for i in vuln_info:
            #Se obtiene la lista de IP
            if int(i[0]) == v:
                ip_list_by_vuln.append(i[2])
                report_vuln_data["NessusID"] = i[0]
                report_vuln_data["Nombre_de_Vulnerabilidad"] = i[1]
                report_vuln_data["Servicio"] = (i[3]).upper() + "/" + i[4]
                report_vuln_data["Severidad"] = i[5]
                report_vuln_data["Prioridad"] = i[6]
                report_vuln_data["Descripcion"] = i[7]
                report_vuln_data["Solucion"] = i[8]
                report_vuln_data["Categoria"] = i[9]
                report_vuln_data["CVE"] = i[10]
                report_vuln_data["CVSS"] = i[11]
                report_vuln_data["Referencias"] = i[12]

        report_vuln_data["ip_list"] = ip_list_by_vuln
        #crear_tabla_reporte(reporte,unicode_string(report_vuln_data["Nombre_de_Vulnerabilidad"]), ip_list_by_vuln,
        #                    unicode_string(report_vuln_data["Servicio"]), report_vuln_data["Prioridad"],
        #                    unicode_string(report_vuln_data["Descripcion"]), unicode_string(report_vuln_data["Solucion"]))
        crear_tabla_reporte(reporte,report_vuln_data)
    return reporte

def add_report_image(reporte, filename):
    href = reporte.addPicture(filename)
    parrafo = P()
    frame = Frame(width="15cm",height="10cm", usertransformed="true", anchortype="paragraph")
    imagen = Image(href=href)

    #Se agrega la imagen al frame
    frame.addElement(imagen)
    #Agregamos el frame al parrafo
    parrafo.addElement(frame)

    #Creamos la tabla de reporte de vulnerabilidad
    tabla = Table()
    tabla.addElement(TableColumn())
    fila = TableRow()
    tabla.addElement(fila)
    celda = TableCell()
    fila.addElement(celda)
    celda.addElement(parrafo)

    #agergamos el parrafo al reporte y lo devolvemos
    reporte.text.addElement(tabla)

    return reporte

def graficar_totales_por_segmento(reporte,segmento,data,graph_file_name):
    '''
    Grafica la seccion de total de vulnerabilidades por segmento con su tabla

    @param reporte: Reporte que se modifica (odf.opendocument.OpenDocumentText())
    @param segmento: Segmento que se quiere graficar (ipcalc.Network())
    @param data: Informacion de las Vulnerabilidades Altas, Medias y bajas (Dict())
    @param graph_file_name: Nombre del archivo de la grafica (str())

    @return reporte: Reporte que se modifica (odf.opendocument.OpenDocumentText())
    '''

    colors = ('red','yellow','green')
    labels = data.keys()
    values = data.values()
    titulo = ""

    totales_por_tabla(reporte,data)
    reporte.text.addElement(P(text="\n"))
    reporte.text.addElement(P(text="\n"))

    if graph_file_name == "out/img/vbarchart-TOTALES.png":
        titulo = "Total"
    else:
        titulo = "Total de Vulnerabilidades por criticidad en el segmento: " + str(segmento.network()) +"/" + str(segmento.subnet())

    dibujar_grafica_barras_verticales(labels, values,titulo , colors=colors, graph_file_name=graph_file_name)

    add_report_image(reporte,graph_file_name)
    reporte.text.addElement(P(text="\n"))
    reporte.text.addElement(P(text="\n"))

    return reporte

def graficar_totales_por_criticidad_en_segmento(reporte,segmento,data,criticidad,graph_file_name):
    '''
    Grafica la seccion de total de vulnerabilidades por criticidad en el segmento

    @param reporte: Reporte que se modifica (odf.opendocument.OpenDocumentText())
    @param segmento: Segmento que se quiere graficar (ipcalc.Network())
    @param data: Informacion de las Vulnerabilidades Altas, Medias y bajas (Dict())
    @param graph_file_name: Nombre del archivo de la grafica (str())

    @return reporte: Reporte que se modifica (odf.opendocument.OpenDocumentText())
    '''
    #colors = ('red','yellow','green')
    labels = data.keys()
    values = data.values()
    crit_title = ""

    if criticidad == 0: #Informativa
        crit_title = "Informativa"
    elif criticidad == 1: #Baja
        crit_title = "Baja"
    elif criticidad == 2: #Media
        crit_title = "Media"
    elif criticidad >= 3: # Alta
        crit_title = "Alta"


    reporte.text.addElement(P(text="\n"))
    reporte.text.addElement(P(text="\n"))

    dibujar_grafica_pastel(labels, values, "Total de Vulnerabilidades por criticidad " + crit_title + " en el segmento: " + str(segmento.network()) +"/" +
                                      str(segmento.subnet()), graph_file_name=graph_file_name)

    add_report_image(reporte,graph_file_name)
    reporte.text.addElement(P(text="\n"))
    reporte.text.addElement(P(text="\n"))