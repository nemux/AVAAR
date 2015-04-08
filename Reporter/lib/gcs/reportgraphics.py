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
from time import sleep

__author__ = "NeMuX"
__copyright__ = "Copyright 2014"
__credits__ = ["NeMuX"]
__license__ = "Apache 2.0"
__version__ = "0.1"
__maintainer__ = "NeMuX"
__email__ = "jaraujo@globalcybersec.com"
__status__ = "Development"

import matplotlib.pyplot
from gcs.utils import *

def dibujar_grafica_pastel(labels, values, title, colors=None, graph_file_name="piechart.png", sort_legend=False):

    if len(labels) == len(values):
        graph_labels = tuple(labels)
        graph_values = tuple(values)

        labels_size = len(labels)

        if colors != None and len(colors) == len(labels):
            colors = tuple(colors)
        graph_info, pie_texts, pie_values = matplotlib.pyplot.pie(graph_values, colors=colors, shadow=True,
                                                        startangle=90, radius=1, autopct='%1.1f%%' )

        #labels = ['{0} - {1:} '.format(i.encode('utf-8'),j) for i,j in zip(labels, graph_values)]
        labels2 = []
        for i,j in zip(labels, graph_values):
            #print(i + "\n")
            #print(str(j) + "\n")
            labels.append('{0} - {1:}'.format(i.encode("utf-8"),str(j)))
            #labels.append('{0}-{1:}'.format(unicode_string(i),str(j)))



        if sort_legend:
            graph_info, labels, values =  zip(*sorted(zip(graph_info, labels, graph_values),
                                                  key=lambda x: x[1],
                                                  reverse=False))
        for i in labels[labels_size:]:
            labels2.append(unicode_string(i))

        #for j in labels2:
        #    print(j)

        matplotlib.pyplot.legend(graph_info, labels2, loc='upper left', bbox_to_anchor=(-0.3, 1.),
                                 fontsize=10)
        matplotlib.pyplot.title(title)


        matplotlib.pyplot.savefig(graph_file_name, bbox_inches='tight')
        #matplotlib.pyplot.show()
        matplotlib.pyplot.clf()
    else:
        print(u"Los argumentos labels y value deben tener el mismo tama\u00F1o")


def dibujar_grafica_barras_horizontales(labels, values, title, colors=None, graph_file_name="hbarchart.png",
                                        sort_legend=False):

    if len(labels) == len(values):

        graph_labels = tuple(labels)
        graph_labels_size = range(len(list(labels)))
        graph_values = tuple(values)

        if colors != None and len(colors) == len(labels):
            colors = tuple(colors)
        x_size = max(values) * 0.1 + max(values)

        graph_info = matplotlib.pyplot.barh(graph_labels_size,graph_values , align='center', alpha=1.0, color=colors)
        matplotlib.pyplot.yticks(graph_labels_size,labels)

        sizes = [graph_labels[c] + "(" + str(graph_info[c].get_width()) + ")"
                 for c in range(len(graph_info))]

        if sort_legend:
            graph_info, graph_labels = zip(*sorted(zip(graph_info, sizes),
                                                  key=lambda x: x[1],
                                                  reverse=False))
            sizes = graph_labels
        matplotlib.pyplot.title(title)
        matplotlib.pyplot.legend(graph_info, sizes, loc='upper right', bbox_to_anchor=(1.3, 1.0),
                                     fontsize=10, shadow="true")

        matplotlib.pyplot.xlim(xmax=x_size)
        matplotlib.pyplot.xlabel("Numero de Vulnerabilidades")
        matplotlib.pyplot.xticks()

        matplotlib.pyplot.savefig(graph_file_name, bbox_inches='tight')
        #matplotlib.pyplot.show()
        matplotlib.pyplot.clf()
    else:
        print(u"Los argumentos labels y value deben tener el mismo tama\u00F1o")

def dibujar_grafica_barras_verticales(labels, values, title, colors=None, graph_file_name="vbarchart.png",
                                        sort_legend=False):
    if len(labels) == len(values):
        x = range(len(values))
        y_size = max(values) * 0.1 + max(values)
        x_size = max(values) * 0.1 + max(values)
        graph_values = tuple(values)
        graph_labels  = tuple(labels)

        if colors != None and len(colors) == len(labels):
            colors = tuple(colors)

        #fig, ax = matplotlib.pyplot.subplots()
        graph_info = matplotlib.pyplot.bar(x,graph_values, color=colors, width=0.5)

        sizes = [ graph_labels[c] + "(" + str(graph_info[c].get_height()) + ")"
                 for c in range(len(graph_info)) ]

        if sort_legend:
            graph_info, graph_labels =  zip(*sorted(zip(graph_info, sizes),
                                                  key=lambda x: x[1],reverse=False))
            sizes = graph_labels
        x_label_pos = [y+0.25 for y in x ]
        matplotlib.pyplot.xlim(xmin=-0.2)
        matplotlib.pyplot.xticks(x_label_pos, labels)
        matplotlib.pyplot.ylim(ymax=y_size)


        matplotlib.pyplot.title(title)
        matplotlib.pyplot.legend(graph_info, sizes, loc='upper right', bbox_to_anchor=(1.3, 1.0),
                                 fontsize=10, shadow="true")
        matplotlib.pyplot.savefig(graph_file_name, bbox_inches='tight')
        #matplotlib.pyplot.show()
        matplotlib.pyplot.clf()
    else:
        print(u"Los argumentos labels y value deben tener el mismo tama\u00F1o")


if __name__ == "__main__":
    values = [1000,30,300,500]
    #values = [800,30,20,100]
    labels=['Altas','Medias','Bajas','Informativas']
    colors = ['red','yellow','green','blue']

    dibujar_grafica_barras_horizontales(labels,values,"Vulnerabilidades por segmento X", colors,sort_legend=True)
    dibujar_grafica_pastel(labels,values,"Vulnerabilidades por segmento X", colors,sort_legend=True)
    dibujar_grafica_barras_verticales(labels,values,"Vulnerabilidades por segmento X",colors,sort_legend=True)