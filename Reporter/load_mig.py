#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
package.module
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
from odf.draw  import Page, Frame, TextBox, Image, FloatingFrame

reporte = OpenDocumentText()
href = reporte.addPicture("piechart.png")

Pa = P()
df =
img = Image(href=href)



df.addElement(img)
Pa.addElement(df)

reporte.text.addElement(Pa)


def add_report_image(reporte, filename):
    href = reporte.addPicture(filename)
    parrafo = P()
    frame = Frame(width="15cm",height="10cm", usertransformed="true", anchortype="paragraph")
    imagen = Image(href=href)

    #Se agrega la imagen al frame
    frame.addElement(imagen)
    #Agregamos el frame al parrafo
    parrafo.addElement(frame)

    #agergamos el parrafo al reporte y lo devolvemos
    reporte.text.addElement(parrafo)

    return reporte







reporte.save("Doc_Imagen",addsuffix=True)