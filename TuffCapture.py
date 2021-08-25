import sys
import os
import subprocess
import re
import time
import datetime
import pickle
import contextlib
import scapy
from scapy.all import hexdump, AsyncSniffer,sniff, compile_filter, conf, Ether, IP, TCP, UDP, ARP, ICMP, get_if_addr, rdpcap, wrpcap
from PyQt5.QtWidgets import QAction, QDateEdit, QDialog, QApplication, QMainWindow, QPushButton, QLabel, QMessageBox, QTextEdit, QTreeWidget, QFileDialog, QTreeWidgetItem, QSpinBox, QComboBox, QHBoxLayout, QLineEdit
from PyQt5.QtCore import QTime, QTimer, Qt, pyqtSignal, QThread
from PyQt5.QtGui import QBrush, QColor, QMovie, QCursor
from PyQt5 import uic
from sqlite3 import connect
from io import StringIO
from classes.FilterWindow import FilterWindow
from classes.IPWindow import IPWindowz
from classes.FilterSupport import FilterSupport
from classes.PrimaryWindow import PrimaryWindow

#main window class
class TuffCapture(QMainWindow):

	def __init__(self):
		super().__init__()

		#load template
		uic.loadUi("templates/MainTemplate.ui", self)

		#find children class
		self.startCapturing = self.findChild(QPushButton, "startCapturing")
		self.stopCapturing = self.findChild(QPushButton, "stopCapturing")
		self.save = self.findChild(QPushButton, "save")
		self.open = self.findChild(QPushButton, "open")
		self.hexButton = self.findChild(QPushButton, "hexButton")
		self.clearScreen = self.findChild(QPushButton, "clearScreen")
		self.filter = self.findChild(QPushButton, "filter")
		self.packsViewer = self.findChild(QTreeWidget, "packsViewer")
		self.onePackViewer = self.findChild(QTreeWidget, "onePackViewer")
		self.hexText = self.findChild(QTextEdit, "hexText")
		self.totalNumPage = self.findChild(QLabel, "totalNumPage")
		self.spinPageNum = self.findChild(QSpinBox,"spinPageNum")
		self.numPackets = self.findChild(QLabel, "numPackets")
		self.numDisplayed = self.findChild(QLabel, "numDisplayed")
		self.loadingGif = self.findChild(QLabel, "loadingGif")
		self.loadingText = self.findChild(QLabel, "loadingText")
		self.filterSearchBar = self.findChild(QLineEdit, "filterSeachBar")
		self.showIpAddr = self.findChild(QLabel, "showIpAddr")
		self.captureSide = self.findChild(QPushButton, "captureSide")
		self.dbSide = self.findChild(QPushButton, "dbSide")
		self.filterDateSet = self.findChild(QPushButton, "filterDateSet")
		self.clearFilterSearchBar = self.findChild(QPushButton, "clearFilterSearchBar")
		self.previousPacket = self.findChild(QPushButton, "previousPacket")
		self.nextPacket = self.findChild(QPushButton, "nextPacket")
		self.deleteFromDB = self.findChild(QPushButton, "deleteFromDB")
		self.IPWindow = self.findChild(QPushButton, "ips")
		self.menuNew = self.findChild(QAction, "menuNew")
		self.menuOpen = self.findChild(QAction, "menuOpen")
		self.menuSave = self.findChild(QAction, "menuSave")
		self.menuSaveAs = self.findChild(QAction, "menuSaveAs")
		self.menuExit = self.findChild(QAction, "menuExit")
		self.sendToDB = self.findChild(QPushButton, "sendToDB")
		self.filterSyntaxHelp = self.findChild(QPushButton, "filterSyntaxHelp")
		self.toggleMode = self.findChild(QPushButton, "toggleMode")

		#signal link
		self.startCapturing.clicked.connect(self.started)
		self.stopCapturing.clicked.connect(self.stoped)
		self.save.clicked.connect(self.saveFile)
		self.open.clicked.connect(self.openThreadStart)
		self.filter.clicked.connect(self.toggleFilter)
		self.hexButton.clicked.connect(self.showHex)
		self.clearScreen.clicked.connect(self.clearScreenEvent)
		self.packsViewer.currentItemChanged.connect(self.listSelect)
		self.spinPageNum.valueChanged.connect(self.pageNumChange)
		self.filterSearchBar.textChanged.connect(self.filterSearchBarChanged)
		self.captureSide.clicked.connect(self.captureSideClicked)
		self.dbSide.clicked.connect(self.dbSideClicked)
		self.filterSearchBar.returnPressed.connect(self.filterSearchBarApply)
		self.clearFilterSearchBar.clicked.connect(lambda: self.filterSearchBar.setText(""))
		self.previousPacket.clicked.connect(self.previousPacketClicked)
		self.nextPacket.clicked.connect(self.nextPacketClicked)
		self.deleteFromDB.clicked.connect(self.deleteFromDBClicked)
		self.IPWindow.clicked.connect(self.IPWindowClicked)
		self.menuNew.triggered.connect(self.clearScreenEvent)
		self.menuOpen.triggered.connect(self.openThreadStart)
		self.menuSave.triggered.connect(self.saveFile)
		self.menuSaveAs.triggered.connect(self.saveFile)
		self.menuExit.triggered.connect(self.close)
		self.sendToDB.clicked.connect(self.saveDB)
		self.filterSyntaxHelp.clicked.connect(self.filterSyntaxHelpClicked)
		self.toggleMode.clicked.connect(self.toggleClick)
		
		#initial values
		self.ipsList = []
		self.dbNumRows = 0
		self.dbSideStatus = False
		self.iface = "wlo1"
		self.filterSearchBarStatus = False
		self.openedCapFile = scapy.plist.PacketList()
		self.openedFileName = ""
		self.saveLiveFileName = ""
		self.filterStr = ""
		self.filterDate = ""
		self.filterStatus = False
		self.tempFilesNames = []
		self.currentPageIndex = 0
		self.maxPagesIndex = 0
		self.currentPacketIndex = 0
		self.currentPackets = scapy.plist.PacketList()
		self.packsViewer.setColumnWidth(0,70)
		self.packsViewer.setColumnWidth(1,80)
		self.packsViewer.setColumnWidth(2,65)
		self.packsViewer.setColumnWidth(3,130)
		self.packsViewer.setColumnWidth(4,130)
		self.packsViewer.setColumnWidth(5,70)
		self.packsViewer.setColumnWidth(6,60)
		self.stopCapturing.setCursor(QCursor(Qt.PointingHandCursor))
		self.stopCapturing.setEnabled(False)
		self.save.setEnabled(False)
		self.sendToDB.setEnabled(False)
		self.hexText.setVisible(False)
		self.hexText.setReadOnly(True)
		self.loadingGif.hide()
		self.loadingText.hide()
		self.captureSide.setEnabled(False)
		self.deleteFromDB.setEnabled(False)
		self.packsViewer.setRootIsDecorated(False)
		self.menuOpen.setEnabled(self.open.isEnabled())
		self.menuSave.setEnabled(self.save.isEnabled())

		#temp files
		os.system("mkdir /tmp/live")
		os.system("mkdir /tmp/open")
		os.system("mkdir /tmp/filter")
		os.system("mkdir /tmp/db")

		#GIF for loadingGif
		self.gifImg = QMovie("resources/loading.gif")
		self.loadingGif.setMovie(self.gifImg)
		self.gifImg.start()

		#StyleSheets
		with open("stylesheets/darkmode.css", "r") as f: self.darkmode = f.read()
		with open("stylesheets/lightmode.css", "r") as f: self.lightmode = f.read()
		
		#Join the dark side
		with open("stylesheets/QPushButtonNotActiveD.css", "r") as f: self.QPushButtonNotActiveD = f.read()
		with open("stylesheets/QPushButtonActiveD.css", "r") as f: self.QPushButtonActiveD = f.read()
		with open("stylesheets/filterSearchBarOriginalD.css", "r") as f: self.filterSearchBarOriginalD = f.read()
		with open("stylesheets/filterSearchBarValidD.css", "r") as f: self.filterSearchBarValidD = f.read()
		with open("stylesheets/filterSearchBarErrorD.css", "r") as f: self.filterSearchBarErrorD = f.read()
		with open("stylesheets/captureSidedbSideD.css", "r") as f: self.captureSidedbSideD = f.read()
		with open("stylesheets/filterWindowStyleD.css", "r") as f: self.filterWindowStyleD = f.read()

		#lightmode elementary styles
		with open("stylesheets/QPushButtonNotActiveL.css", "r") as f: self.QPushButtonNotActiveL = f.read()
		with open("stylesheets/QPushButtonActiveL.css", "r") as f: self.QPushButtonActiveL = f.read()
		with open("stylesheets/filterSearchBarOriginalL.css", "r") as f: self.filterSearchBarOriginalL = f.read()
		with open("stylesheets/filterSearchBarValidL.css", "r") as f: self.filterSearchBarValidL = f.read()
		with open("stylesheets/filterSearchBarErrorL.css", "r") as f: self.filterSearchBarErrorL = f.read()
		with open("stylesheets/captureSidedbSideL.css", "r") as f: self.captureSidedbSideL = f.read()

		self.currentMode = self.darkmode
		self.setStyleSheet(self.currentMode)

		#show IP address
		self.showIpAddr.setText(f"MyIP: {get_if_addr(conf.iface)}")

		#PrimaryWindow
		self.PrimaryWindow = PrimaryWindow(self.currentMode)
		self.PrimaryWindow.setStyleSheet(self.currentMode)

		self.PrimaryWindow.startedSig.connect(self.PrimaryWindowStarted)
		self.PrimaryWindow.dbSig.connect(self.dbSigTriggered)
		self.PrimaryWindow.openSig.connect(self.openSigTriggered)
		self.PrimaryWindow.show()

	def toggleClick(self):
		if self.currentMode == self.darkmode:
			self.currentMode = self.lightmode
			self.setStyleSheet(self.currentMode)

			self.captureSide.setStyleSheet(self.captureSidedbSideL)
			self.dbSide.setStyleSheet(self.captureSidedbSideL)

			if self.hexButton.styleSheet() == self.QPushButtonActiveD:
				self.hexButton.setStyleSheet(self.QPushButtonActiveL)
			elif self.hexButton.styleSheet() == self.QPushButtonNotActiveD:
				self.hexButton.setStyleSheet(self.QPushButtonNotActiveL)

			if self.filter.styleSheet() == self.QPushButtonActiveD:
				self.filter.setStyleSheet(self.QPushButtonActiveL)
			elif self.filter.styleSheet() == self.QPushButtonNotActiveD:
				self.filter.setStyleSheet(self.QPushButtonNotActiveL)

			if self.filterSearchBar.styleSheet() == self.filterSearchBarOriginalD:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarOriginalL)
			elif self.filterSearchBar.styleSheet() == self.filterSearchBarValidD:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarValidL)
			elif self.filterSearchBar.styleSheet() == self.filterSearchBarErrorD:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarErrorL)

			self.clearFilterSearchBar.setStyleSheet("color:#FAFAFA;")
			self.filterSyntaxHelp.setStyleSheet("color:#FAFAFA;")

		elif self.currentMode == self.lightmode:
			self.currentMode = self.darkmode
			self.setStyleSheet(self.currentMode)

			self.captureSide.setStyleSheet(self.captureSidedbSideD)
			self.dbSide.setStyleSheet(self.captureSidedbSideD)

			if self.hexButton.styleSheet() == self.QPushButtonActiveL:
				self.hexButton.setStyleSheet(self.QPushButtonActiveD)
			elif self.hexButton.styleSheet() == self.QPushButtonNotActiveL:
				self.hexButton.setStyleSheet(self.QPushButtonNotActiveD)

			if self.filter.styleSheet() == self.QPushButtonActiveL:
				self.filter.setStyleSheet(self.QPushButtonActiveD)
			elif self.filter.styleSheet() == self.QPushButtonNotActiveL:
				self.filter.setStyleSheet(self.QPushButtonNotActiveD)

			if self.filterSearchBar.styleSheet() == self.filterSearchBarOriginalL:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarOriginalD)
			elif self.filterSearchBar.styleSheet() == self.filterSearchBarValidL:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarValidD)
			elif self.filterSearchBar.styleSheet() == self.filterSearchBarErrorL:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarErrorD)

			self.clearFilterSearchBar.setStyleSheet("color:#FAFAFA;")
			self.filterSyntaxHelp.setStyleSheet("color:#FAFAFA;")

	def openSigTriggered(self, fileName):
			self.show()

			#start loading GIF
			self.loadingGifStart("Opening")
			
			#set buttons
			self.clearScreen.setEnabled(False)
			self.startCapturing.setEnabled(False)
			self.filter.setEnabled(False)
			self.spinPageNum.setEnabled(False)
			self.sendToDB.setEnabled(True)

			#start OpenThread
			self.openThread = OpenThread(fileName, self.filterStatus, self.filterStr)
			self.openThread.start()
			self.openThread.showOpenedFile.connect(self.showOpenedFile)
			self.openThread.configurePacketsDisplayed.connect(self.setPacketsAndDisplayed)
			self.openThread.filterSnifferFinishedSignal.connect(self.filterSnifferFinished)
			self.openThread.finished.connect(self.openThreadFinished)
			self.openThread.loadingGifStart.connect(lambda: self.loadingGifStart("Filtering"))

	def dbSigTriggered(self):
		self.show()
		self.dbSideClicked()

	def PrimaryWindowStarted(self, iface, filterStr):
		self.show()
		if iface=="All":
			self.iface=None
		else:
			self.iface=iface
		self.filterStr = filterStr
		if self.filterStr != "":
			if self.currentMode == self.darkmode:
				self.filter.setStyleSheet(self.QPushButtonActiveD)
			elif self.currentMode == self.lightmode:
				self.filter.setStyleSheet(self.QPushButtonActiveL)			
			self.filterStatus = True
		self.filterSearchBar.setText(self.filterStr)
		self.started()

	def filterSyntaxHelpClicked(self):
		self.filterSupport = FilterSupport()
		self.filterSupport.setStyleSheet(self.currentMode)

	def IPWindowClicked(self):
		self.IPWindow = IPWindowz(get_if_addr(conf.iface), self.ipsList)
		self.IPWindow.setStyleSheet(self.currentMode)

	def deleteFromDBClicked(self):
		if self.filterStatus:
			self.ask5 = QMessageBox.question(self, "Delete From Database", "Do you want to delete filtred packets from database ?")
			if self.ask5 == QMessageBox.Yes:

				self.loadingGifStart("Deleting from database!")

				self.deleteFromDbThread = DeleteFromDbThread(True)
				self.deleteFromDbThread.start()
				self.deleteFromDbThread.finished.connect(lambda: self.loadingGifStop("Deleting finished."))
			elif self.ask5 == QMessageBox.No:
				return

		else:
			self.ask5 = QMessageBox.question(self, "Delete From Database", "Are you sure you want to delete all packets in the database?")
			if self.ask5 == QMessageBox.Yes:

				self.loadingGifStart("Deleting from database")

				self.deleteFromDbThread = DeleteFromDbThread(False)
				self.deleteFromDbThread.start()
				self.deleteFromDbThread.finished.connect(self.deleteFromDBfinished)
			elif self.ask5 == QMessageBox.No:
				return

		self.onePackViewer.clear()
		self.hexText.setText("")
		self.packsViewer.clear()

	def deleteFromDBfinished(self):
		self.loadingGifStop("Deleting finished!")
		self.dbSideClicked()

	def nextPacketClicked(self):
		if self.packsViewer.currentIndex().row()<1000:
			self.packsViewer.setCurrentItem(self.packsViewer.itemBelow(self.packsViewer.currentItem()))

	def previousPacketClicked(self):
		if self.packsViewer.currentIndex().row()>0:
			self.packsViewer.setCurrentItem(self.packsViewer.itemAbove(self.packsViewer.currentItem()))

	def filterSearchBarApply(self):
		if self.filterSearchBarStatus:
			self.filterStatus = True
			if self.currentMode == self.darkmode:
				self.filter.setStyleSheet(self.QPushButtonActiveD)
			elif self.currentMode == self.lightmode:
				self.filter.setStyleSheet(self.QPushButtonActiveL)	

			self.loadingGifStart("Filtering")

			self.maxPagesIndex = 0
			self.tempFilesNames = []
			self.currentPageIndex = 0
			self.currentPacketIndex = 0
			self.currentPackets = scapy.plist.PacketList()
			self.packsViewer.clear()
			self.onePackViewer.clear()
			self.hexText.setText("")
			self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))

			self.filterThread = FilterThread(self.openedFileName, self.saveLiveFileName, self.save.isEnabled(), self.filterStr)
			self.filterThread.start()
			self.filterThread.filterSnifferFinishedSignal.connect(self.filterSnifferFinished)
			self.filterThread.loadingGifStop.connect(self.loadingGifStop)
			

	def captureSideClicked(self):

		self.spinPageNum.setValue(1)
		
		self.removeTempFiles()

		self.dbSideStatus = False
		self.loadingText.hide()
		self.captureSide.setEnabled(False)
		self.clearScreen.setEnabled(True)
		self.dbSide.setEnabled(True)
		self.startCapturing.setEnabled(True)
		self.open.setEnabled(True)
		self.deleteFromDB.setEnabled(False)
		self.menuOpen.setEnabled(self.open.isEnabled())
		self.filterSearchBar.setPlaceholderText("Filter/Search in the output")
		self.removeTempFiles(liveS=False, openS=False)
		self.onePackViewer.clear()
		self.hexText.setText("")
		self.packsViewer.clear()
		self.currentPackets = scapy.plist.PacketList()
		self.ipsList = []


		liveNameLst = sorted([name for name in os.listdir('/tmp/live/')])
		if liveNameLst != []:
			self.save.setEnabled(True)
			self.sendToDB.setEnabled(True)
		self.menuSave.setEnabled(self.save.isEnabled())

		try:
			if self.createDBtempFiles.isRunning():
				self.createDBtempFiles.quit()
				self.loadingGifStop("Aborted action!")
		except:
			pass

		try:
			if self.DeleteFromDbThread.isRunning():
				self.DeleteFromDbThread.quit()
				self.loadingGifStop("Aborted action!")
		except:
			pass

		if self.filterStatus:
			self.toggleFilter()
		else:
			self.currentPackets = scapy.plist.PacketList()
			self.currentPacketIndex = 0
			self.currentPageIndex = 0

			openNameLst = sorted([name for name in os.listdir('/tmp/open/')])

			if openNameLst != []:
				pList = rdpcap(f"/tmp/open/{openNameLst[self.currentPageIndex]}")
				self.totalNumPage.setText(f"/ {len(openNameLst)}")
				self.spinPageNum.setMaximum(len(openNameLst))
				lastpack = rdpcap(f"/tmp/open/{openNameLst[-1]}")
				self.numPackets.setText(f"Packets: {len(lastpack)+1000*len(openNameLst)}")
				self.numDisplayed.setText(f"Displayed: {len(lastpack)+1000*len(openNameLst)}")
			elif liveNameLst != []:
				pList = rdpcap(f"/tmp/live/{liveNameLst[self.currentPageIndex]}")
				self.totalNumPage.setText(f"/ {len(liveNameLst)}")
				self.spinPageNum.setMaximum(len(liveNameLst))
				lastpack = rdpcap(f"/tmp/live/{liveNameLst[-1]}")
				self.numPackets.setText(f"Packets: {len(lastpack)+1000*len(liveNameLst)}")
				self.numDisplayed.setText(f"Displayed: {len(lastpack)+1000*len(liveNameLst)}")
			else:
				self.totalNumPage.setText("/ 1")
				self.spinPageNum.setMaximum(1)
				self.numPackets.setText(f"Packets: 0")
				self.numDisplayed.setText(f"Displayed: 0")
				return

			for pack in pList:
				self.onePackProcess(pack)


	def dbSideClicked(self):
		
		if not self.startCapturing.isEnabled():
			return

		elif self.save.isEnabled():
			self.ask6 = QMessageBox()
			self.ask6.setWindowTitle("Unsaved Data Detected!")
			self.ask6.setWindowModality(Qt.NonModal)
			self.saveToFile = self.ask6.addButton('File', self.ask6.ActionRole)
			self.saveToDB = self.ask6.addButton('Database', self.ask6.ActionRole)
			self.discard = self.ask6.addButton('Discard', self.ask6.ActionRole)
			self.cancel = self.ask6.addButton('Cancel', self.ask6.RejectRole)
			self.ask6.setText("You still have unsaved data, where do you want to save it?")

			self.saveToFile.clicked.connect(self.saveFile)
			self.saveToDB.clicked.connect(self.saveDB)

			returnedValue = self.ask6.exec_()
			if returnedValue == 3:
				return

		self.removeTempFiles()
		self.dbSideStatus=True
		self.clearScreen.setEnabled(False)
		self.sendToDB.setEnabled(False)
		self.captureSide.setEnabled(True)
		self.save.setEnabled(False)
		self.dbSide.setEnabled(False)
		self.startCapturing.setEnabled(False)
		self.open.setEnabled(False)
		self.menuOpen.setEnabled(self.open.isEnabled())
		self.menuSave.setEnabled(self.save.isEnabled())
		self.filterSearchBar.setPlaceholderText("Filter/Search In Database")
		self.currentPackets = scapy.plist.PacketList()
		self.currentPacketIndex = 0
		self.tempFilesNames = []
		self.ipsList = []
		self.maxPagesIndex = 0
		self.currentPageIndex = 0

		if self.filterStatus:
			self.toggleFilter()

		con = connect('tuff.db')
		cur = con.cursor()

		cur.execute("select count(*) from maintable")
		self.dbNumRows = cur.fetchone()[0]
		if self.dbNumRows!=0:
			self.deleteFromDB.setEnabled(True)
		self.maxPagesIndex = self.dbNumRows//1000

		#set and reset
		self.spinPageNum.setMaximum(self.maxPagesIndex+1)
		self.currentPackets = scapy.plist.PacketList()
		self.currentPacketIndex = 0
		self.currentPageIndex = 0
		self.packsViewer.clear()
		self.onePackViewer.clear()
		self.hexText.setText("")
		self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))

		self.numPackets.setText(f"Packets: {self.dbNumRows}")
		self.numDisplayed.setText(f"Displayed: {self.dbNumRows}")

		self.loadingText.show()
		self.loadingGif.show()
		self.loadingText.setText("Filter is not ready yet ...")
		self.filterSearchBar.setEnabled(False)
		self.filter.setEnabled(False)
		
		#load the first page
		if self.spinPageNum.value()==1:
			cur.execute("Select Date, Time, MACsource, MACdest, IPsource, IPdest, Protocol, len, info, binary from maintable limit 1000")
			for row in cur.fetchall():
				self.onePackProcess(pickle.loads(row[9]), row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8])
		else:
			self.spinPageNum.setValue(1)

		con.commit()
		con.close()

		self.createDBtempFiles = CreateDbTempFileThread()
		self.createDBtempFiles.start()
		self.createDBtempFiles.sendIpsList.connect(self.createDBtempFilesFinished)

	def createDBtempFilesFinished(self, ipsList):
		self.ipsList = ipsList
		self.loadingText.setText("Filter is ready")
		self.loadingGif.hide()
		self.filterSearchBar.setEnabled(True)
		self.filter.setEnabled(True)

	def filterSearchBarChanged(self):
		self.filterStr = self.filterSearchBar.text()
		if self.filterStr == "":
			if self.currentMode == self.darkmode:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarOriginalD)
			elif self.currentMode == self.lightmode:
				self.filterSearchBar.setStyleSheet(self.filterSearchBarOriginalL)
			self.filterSearchBarStatus = False
			if self.filterStatus:
				self.toggleFilter()
		else:
			#validate filter
			dateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d))(?: and)?")
			dateToDateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)) to (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)(?: and)?")

			dateAndList = re.findall(dateAndPattern, self.filterStr)
			dateToDateAndList = re.findall(dateToDateAndPattern, self.filterStr)

			self.filterStrParsed = self.filterStr

			if dateToDateAndList!=[]:
				if len(dateToDateAndList)==1:
					self.filterStrParsed=" and ".join(list(filter(None,self.filterStr.split(dateToDateAndList[0]))))
			elif dateAndList!=[]:
				if len(dateAndList)==1:
					self.filterStrParsed=" and ".join(list(filter(None,self.filterStr.split(dateAndList[0]))))
					
			try:
				compile_filter(self.filterStrParsed)
				if self.currentMode == self.darkmode:
					self.filterSearchBar.setStyleSheet(self.filterSearchBarValidD)
				elif self.currentMode == self.lightmode:
					self.filterSearchBar.setStyleSheet(self.filterSearchBarValidL)
				self.filterSearchBarStatus = True
			except:
				if self.currentMode == self.darkmode:
					self.filterSearchBar.setStyleSheet(self.filterSearchBarErrorD)
				elif self.currentMode == self.lightmode:
					self.filterSearchBar.setStyleSheet(self.filterSearchBarErrorL)
				self.filterSearchBarStatus = False

	def started(self):

		#check for unsaved data
		liveTempFiles = sorted([name for name in os.listdir('/tmp/live/')])
		if liveTempFiles!=[]:
			self.ask1 = QMessageBox()
			self.ask1.setWindowTitle("Unsaved Data Detected!")
			self.ask1.setWindowModality(Qt.NonModal)
			self.saveToFile = self.ask1.addButton('File', self.ask1.ActionRole)
			self.saveToDB = self.ask1.addButton('Database', self.ask1.ActionRole)
			self.discard = self.ask1.addButton('Discard', self.ask1.ActionRole)
			self.cancel = self.ask1.addButton('Cancel', self.ask1.RejectRole)
			self.ask1.setText("You have unsaved data, where do you want to save it?")

			self.saveToFile.clicked.connect(self.saveFile)
			self.saveToDB.clicked.connect(self.saveDB)

			returnedValue = self.ask1.exec_()
			if returnedValue == 3:
				return

		#remove all temp files
		self.removeTempFiles()
		
		#set and reset
		self.packsViewer.clear()
		self.hexText.setText("")
		self.onePackViewer.clear()
		self.currentPackets = scapy.plist.PacketList()

		self.spinPageNum.setMaximum(1)
		self.tempFilesNames = []
		self.ipsList = []
		self.currentPacketIndex = 0
		self.currentPageIndex = 0
		self.maxPagesIndex = 0
		self.totalNumPage.setText("/ 1")
		self.spinPageNum.setEnabled(False)

		self.openedFileName = ""
		self.saveLiveFileName = ""
		self.dbSideStatus = False

		self.save.setEnabled(False)
		self.sendToDB.setEnabled(False)
		self.clearScreen.setEnabled(False)
		self.startCapturing.setEnabled(False)
		self.stopCapturing.setEnabled(True)
		self.open.setEnabled(False)
		self.filter.setEnabled(False)
		self.clearFilterSearchBar.setEnabled(False)

		#loadingGIF start
		self.loadingGifStart("Capturing")

		#start sniffer thread
		self.snifferThread=SnifferThread(self.iface, self.filterStr)
		self.snifferThread.start()
		self.snifferThread.sendPackSignal.connect(self.onePackProcess)

	def stoped(self):
		#loadingGIF stop
		self.loadingGifStop("Done Capturing!")

		#stop capturing
		self.snifferThread.terminate()
		
		#set and reset
		self.open.setEnabled(True)
		self.clearScreen.setEnabled(True)
		self.startCapturing.setEnabled(True)
		self.stopCapturing.setEnabled(False)
		self.filter.setEnabled(True)
		self.spinPageNum.setEnabled(True)
		self.clearFilterSearchBar.setEnabled(True)

		self.numPackets.setText(f"Packets: {len(self.currentPackets)+1000*self.maxPagesIndex}")
		self.numDisplayed.setText(f"Displayed: {len(self.currentPackets)+1000*self.maxPagesIndex}")

		#create the last live temp file
		if list(self.currentPackets)!=[]:
			newLiveFileName = f"temp_{str(self.maxPagesIndex).zfill(5)}.cap"
			self.tempFilesNames.append(newLiveFileName)
			wrpcap(f"/tmp/live/{newLiveFileName}", self.currentPackets)

		#reset spinbox after capture
		self.spinPageNum.setMaximum(self.maxPagesIndex+1)
		self.spinPageNum.setValue(self.maxPagesIndex+1)

		#ask to save data
		if list(self.currentPackets) != []:
			self.ask2 = QMessageBox()
			self.ask2.setWindowTitle("Save Captured Packets")
			self.ask2.setWindowModality(Qt.NonModal)
			self.saveToFile = self.ask2.addButton('File', self.ask2.ActionRole)
			self.saveToDB = self.ask2.addButton('Database', self.ask2.ActionRole)
			self.cancel = self.ask2.addButton("Cancel", self.ask2.RejectRole)
			self.ask2.setText("Save Captured Packets")

			self.saveToFile.clicked.connect(self.saveFile)
			self.saveToDB.clicked.connect(self.saveDB)
			self.cancel.clicked.connect(self.enableSaving)

			returnedValue = self.ask2.exec_()

	def enableSaving(self):
		self.save.setEnabled(True)
		self.sendToDB.setEnabled(True)

	def saveDB(self):
		self.save.setEnabled(False)
		self.sendToDB.setEnabled(False)
		self.loadingGifStart("Transferring To Database")
		if [name for name in os.listdir('/tmp/filter/')] != []:
			self.liveToDB = SendToDBThread("filter")
			self.liveToDB.start()
			self.liveToDB.finished.connect(lambda: self.loadingGifStop("Transferring Done!"))
		elif [name for name in os.listdir('/tmp/open/')] != []:
			self.liveToDB = SendToDBThread("open")
			self.liveToDB.start()
			self.liveToDB.finished.connect(lambda: self.loadingGifStop("Transferring Done"))
		elif [name for name in os.listdir('/tmp/live/')] != []:
			self.liveToDB = SendToDBThread("live")
			self.liveToDB.start()
			self.liveToDB.finished.connect(lambda: self.loadingGifStop("Transferring Done!"))

	def onePackProcess(self, pack, Date=0, Time=0, MACsource=0, MACdest=0, IPsource=0, IPdest=0, Protocol=0, length=0, info=0):

		self.currentPackets.append(pack)

		#create live temp files
		if self.dbSideStatus:
			# if self.currentPacketIndex == 1000:
			# 	newLiveFileName = f"temp_{str(self.maxPagesIndex).zfill(5)}.cap"
			# 	self.tempFilesNames.append(newLiveFileName)
			# 	self.currentPageIndex += 1
			# 	self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))
			# 	self.maxPagesIndex += 1
			# 	self.currentPacketIndex = 0
			# 	self.packsViewer.clear()
			# 	self.onePackViewer.clear()
			# 	self.hexText.setText("")
			# 	self.currentPackets = self.currentPackets[1000:]
			if IPsource!="NULL":
				src = IPsource
				dst = IPdest
			else:
				src = MACsource
				dst = MACdest
			proto=Protocol
		else:
			if self.currentPacketIndex == 1000:
				newLiveFileName = f"temp_{str(self.maxPagesIndex).zfill(5)}.cap"
				self.tempFilesNames.append(newLiveFileName)
				wrpcap(f"/tmp/live/{newLiveFileName}", self.currentPackets[:1000])
				self.currentPageIndex += 1
				self.maxPagesIndex += 1
				self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))
				self.currentPacketIndex = 0
				self.packsViewer.clear()
				self.onePackViewer.clear()
				self.hexText.setText("")
				self.currentPackets = self.currentPackets[1000:]
			#get date and time
			packDateTime = datetime.datetime.strptime(time.ctime(int(pack.time))[4:], '%b %d %H:%M:%S %Y')
			Date = packDateTime.strftime("%d-%m-%Y")
			Time = packDateTime.strftime("%H:%M:%S")

			#get src and dst
			if pack.haslayer(IP):
				src = pack[IP].src
				if src not in self.ipsList:
					self.ipsList.append(src)
				dst = pack[IP].dst
				if dst not in self.ipsList:
					self.ipsList.append(dst)
			else:
				src = pack.src
				dst = pack.dst

			#get protocol
			packSummary = pack.summary()[7:]
			if "Raw" in packSummary:
				packSummary = packSummary[:-6]
			elif "Padding" in packSummary:
				packSummary = packSummary[:-10]
			packSummaryLst = packSummary.split("/")
			if "igmp" in packSummaryLst[-1]:
				proto = "IGMP"
			else:
				proto = packSummaryLst[-1].split(" ")[1]
			length = len(pack)
			info = packSummary

		#create item
		line = QTreeWidgetItem([str(self.currentPacketIndex+self.currentPageIndex*1000+1), Date, Time ,src , dst, proto, str(length), info])
		
		#those are just for colorization
		# if pack.haslayer(TCP):
		# 	protoColor = QColor(255,174,174)
		# elif pack.haslayer(UDP):
		# 	protoColor = QColor(179,174,255)
		# elif pack.haslayer(ICMP):
		# 	protoColor = QColor(174,255,209)
		# else:
		# 	protoColor = QColor(219,219,219)
		# for i in range(8):
		# 	line.setBackground(i, QBrush(protoColor))

		#add item to packViewer
		self.packsViewer.addTopLevelItem(line)
		
		self.currentPacketIndex += 1

	def listSelect(self):
		try: #to avoid error
			#reset onePackViewer
			self.onePackViewer.clear()
			#extract packet data
			pid = int(self.packsViewer.currentItem().data(0,0))-self.currentPageIndex*1000
			pack = self.currentPackets[pid-1]
			outputDetailes = self.showOutput(pack, "pack.show()")
			titles = [title.split(" ")[0] for title in outputDetailes.split("###[ ")]

			#create and add parents and children / show info about each packet
			for parent in outputDetailes.split("###[ ")[1:]:
				lines = parent.split("\n")
				parent = lines[0].split(" ")[0]
				childs = lines[1:-1]
				if "Raw" in parent or "Padding" in parent:
					break
				parentItem = QTreeWidgetItem(self.onePackViewer, [parent])
				for child in childs:
					childItem = QTreeWidgetItem(parentItem, [child.strip()])

			#show the hexdump of the packet selected
			self.hexText.setText(self.showOutput(pack, "hexdump(pack)"))
		except:
			pass

	def showOutput(self, pack, expression):
		#Redirect output on the screen to variable 'capture'
		capture = StringIO()
		save_stdout = sys.stdout
		sys.stdout = capture
		eval(expression)
		sys.stdout = save_stdout
		#capture.getvalue() is a string with the output of 'pack.show()' 
		return capture.getvalue()

	def saveFile(self):
		#ask user to enter where to save
		fileURL = QFileDialog.getSaveFileName(self, 'Save Capture file', "capture.cap", "Capture File (*.cap *.pcap)")
		if fileURL[0] != "":
			if self.filterStatus:
				#merge all filter temp files into one file
				files = " ".join(["/tmp/filter/"+name for name in self.tempFilesNames])
				os.system(f"mergecap -w '{fileURL[0]}' {files}")
				self.save.setEnabled(False)
				self.sendToDB.setEnabled(True)
			else:
				#merge all live temp files into one file
				files = " ".join(["/tmp/live/"+name for name in self.tempFilesNames])
				os.system(f"mergecap -w '{fileURL[0]}' {files}")
				self.save.setEnabled(False)
				self.sendToDB.setEnabled(True)
		return fileURL

	def openThreadStart(self):

		#check for unsaved data
		liveTempFiles = sorted([name for name in os.listdir('/tmp/live/')])
		if liveTempFiles!=[]:
			self.ask3 = QMessageBox()
			self.ask3.setWindowTitle("Unsaved Data Detected")
			self.ask3.setWindowModality(Qt.NonModal)
			self.ask3.setText("Where do you want to save captured packets?")
			self.saveToFile = self.ask3.addButton('File', self.ask3.ActionRole)
			self.saveToDB = self.ask3.addButton('Database', self.ask3.ActionRole)
			self.discard = self.ask3.addButton('Discard', self.ask3.ActionRole)
			self.cancel = self.ask3.addButton('Cancel', self.ask3.RejectRole)

			self.saveToFile.clicked.connect(self.saveFile)
			self.saveToDB.clicked.connect(self.saveDB)
			self.discard.clicked.connect(lambda: self.save.setEnabled(False))

			returnedValue = self.ask3.exec_()
			if returnedValue == 3:
				return

		#ask to chose the file to open
		self.openedFileName = QFileDialog.getOpenFileName(self, 'Open Capture file', os.getcwd(), "Capture File (*.cap *.pcap *.pcapng)")[0]

		if self.openedFileName != "":
			#remove all temp files
			self.removeTempFiles()

			#loadingGIF start
			self.loadingGifStart("Opening")
			
			#set buttons
			self.clearScreen.setEnabled(False)
			self.startCapturing.setEnabled(False)
			self.filter.setEnabled(False)
			self.spinPageNum.setEnabled(False)
			self.sendToDB.setEnabled(True)

			self.maxPagesIndex = 0
			self.tempFilesNames = []
			self.currentPageIndex = 0
			self.currentPacketIndex = 0
			self.currentPackets = scapy.plist.PacketList()
			self.ipsList = []
			self.packsViewer.clear()
			self.onePackViewer.clear()
			self.hexText.setText("")
			self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))
			self.dbSideStatus = False

			#start Open Thread
			self.openThread = OpenThread(self.openedFileName, self.filterStatus, self.filterStr)
			self.openThread.start()
			self.openThread.showOpenedFile.connect(self.showOpenedFile)
			self.openThread.configurePacketsDisplayed.connect(self.setPacketsAndDisplayed)
			self.openThread.filterSnifferFinishedSignal.connect(self.filterSnifferFinished)
			self.openThread.finished.connect(self.openThreadFinished)
			self.openThread.loadingGifStart.connect(lambda: self.loadingGifStart("Filtering"))

	def disableSaving(self):
		self.save.setEnabled(False)
		self.sendToDB.setEnabled(False)

	def openThreadFinished(self):
		if not self.filterStatus:
			#loadingGIF stop
			self.loadingGifStop("Done Opening!")

		#reset buttons
		self.clearScreen.setEnabled(True)
		self.startCapturing.setEnabled(True)
		self.filter.setEnabled(True)
		self.spinPageNum.setEnabled(True)

	def showOpenedFile(self, tempFilesNames):
		#set and reset
		self.tempFilesNames = tempFilesNames
		self.maxPagesIndex = len(self.tempFilesNames)-1
		self.currentPacketIndex = 0
		self.currentPageIndex = 0
		self.packsViewer.clear()
		self.onePackViewer.clear()
		self.hexText.setText("")
		self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))
		self.save.setEnabled(False)
		self.spinPageNum.setMaximum(self.maxPagesIndex+1)
		self.spinPageNum.setValue(1)

		#open file
		pList = rdpcap("/tmp/open/"+self.tempFilesNames[0])
		for pack in pList:
			self.onePackProcess(pack)

	def setPacketsAndDisplayed(self, packetsNumStr, numDisplayedStr):
		self.numPackets.setText(packetsNumStr)
		self.numDisplayed.setText(numDisplayedStr)

	def clearScreenEvent(self):
		#check for unsaved data
		liveTempFiles = sorted([name for name in os.listdir('/tmp/live/')])
		if liveTempFiles!=[] and self.save.isEnabled():
			self.ask4 = QMessageBox()
			self.ask4.setWindowTitle("Unsaved Data Detected")
			self.ask4.setWindowModality(Qt.NonModal)
			self.ask4.setText("Where do you want to save captured packets?")
			self.saveToFile = self.ask4.addButton('File', self.ask4.ActionRole)
			self.saveToDB = self.ask4.addButton('Database', self.ask4.ActionRole)
			self.discard = self.ask4.addButton('Discard', self.ask4.ActionRole)
			self.cancel = self.ask4.addButton('Cancel', self.ask4.RejectRole)

			self.saveToFile.clicked.connect(self.saveFile)
			self.saveToDB.clicked.connect(self.saveDB)
			self.discard.clicked.connect(self.disableSaving)

			returnedValue = self.ask4.exec_()
			if returnedValue == 3:
				return

		#remove all temp files
		self.removeTempFiles()

		#set and reset
		self.tempFilesNames = []
		self.totalNumPage.setText("/ 1")
		self.numPackets.setText("Packets: 0")
		self.numDisplayed.setText("Displayed: 0")
		self.openedFileName = ""
		self.saveLiveFileName = ""
		self.maxPagesIndex=0
		self.currentPageIndex=0
		self.spinPageNum.setValue(1)
		self.spinPageNum.setMaximum(1)
		self.currentPacketIndex = 0
		self.packsViewer.clear()
		self.onePackViewer.clear()
		self.hexText.setText("")
		self.currentPackets = scapy.plist.PacketList()
		self.save.setEnabled(False)
		self.sendToDB.setEnabled(False)
		self.loadingText.hide()

	def showHex(self):
		if self.hexText.isVisible():
			if self.currentMode == self.darkmode:
				self.hexButton.setStyleSheet(self.QPushButtonNotActiveD)
			elif self.currentMode == self.lightmode:
				self.hexButton.setStyleSheet(self.QPushButtonNotActiveL)
			self.hexText.setVisible(False)
		else:
			if self.currentMode == self.darkmode:
				self.hexButton.setStyleSheet(self.QPushButtonActiveD)
			elif self.currentMode == self.lightmode:
				self.hexButton.setStyleSheet(self.QPushButtonActiveL)	
			self.hexText.setVisible(True)

	def pageNumChange(self):
		#set and reset
		self.currentPageIndex = self.spinPageNum.value()-1
		self.currentPacketIndex = 0
		self.packsViewer.clear()
		self.onePackViewer.clear()
		self.hexText.setText("")

		#verify the existence of open files first then live files
		openNameLst = sorted([name for name in os.listdir('/tmp/open/')])
		liveNameLst = sorted([name for name in os.listdir('/tmp/live/')])

		if not self.dbSideStatus:
			if self.filterStatus:
				pList = rdpcap(f"/tmp/filter/{self.tempFilesNames[self.currentPageIndex]}")
			elif openNameLst != []:
				pList = rdpcap(f"/tmp/open/{openNameLst[self.currentPageIndex]}")
			elif liveNameLst != []:
				pList = rdpcap(f"/tmp/live/{liveNameLst[self.currentPageIndex]}")
			else:
				return

			for pack in pList:
				self.onePackProcess(pack)
		else:
			if self.filterStatus:
				pList = rdpcap(f"/tmp/filter/{self.tempFilesNames[self.currentPageIndex]}")
				for pack in pList:
					self.onePackProcess(pack)
			else:
				con = connect("tuff.db")
				cur = con.cursor()

				cur.execute(f"select Date, Time, MACsource, MACdest, IPsource, IPdest, Protocol, len, info, binary from maintable limit 1000 offset {self.currentPageIndex*1000}")
				for row in cur.fetchall():
					self.onePackProcess(pickle.loads(row[9]), row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8])

				con.commit()
				con.close()


	def removeTempFiles(self, liveS=True, openS=True, filterS=True):
		if [name for name in os.listdir('/tmp/open/')] != [] and openS:
			os.system("rm /tmp/open/*")
		if [name for name in os.listdir('/tmp/live/')] != [] and openS:
			os.system("rm /tmp/live/*")
		if [name for name in os.listdir('/tmp/filter/')] != [] and filterS:
			os.system("rm /tmp/filter/*")
		if "temp_live.cap" in [name for name in os.listdir('/tmp/')] != []:
			os.system("rm /tmp/temp_live.cap")
		if "temp_db.cap" in [name for name in os.listdir('/tmp/')] != []:
			os.system("rm /tmp/temp_db.cap")


	def colorization(self, pack):
		pass

	def toggleFilter(self):
		if self.filterStatus:
			if self.currentMode == self.darkmode:
				self.filter.setStyleSheet(self.QPushButtonNotActiveD)
			elif self.currentMode == self.lightmode:
				self.filter.setStyleSheet(self.QPushButtonNotActiveL)
			self.loadingText.hide()
			self.filterStatus = False
			self.filterStr = ""

			self.filterSearchBar.setText("")

			openTempFiles = sorted([name for name in os.listdir('/tmp/open/')])
			liveTempFiles = sorted([name for name in os.listdir('/tmp/live/')])

			if not self.dbSideStatus:
				if openTempFiles != []:
					self.numDisplayed.setText(f"Displayed: {len(rdpcap('/tmp/open/'+openTempFiles[-1]))+1000*(len(openTempFiles)-1)}")
					self.loadTempDirectories("open")
				elif liveTempFiles != []:
					self.numDisplayed.setText(f"Displayed: {len(rdpcap('/tmp/live/'+liveTempFiles[-1]))+1000*(len(liveTempFiles)-1)}")
					self.loadTempDirectories("live")
			else:
				self.numPackets.setText(f"Packets: {self.dbNumRows}")
				self.numDisplayed.setText(f"Displayed: {self.dbNumRows}")
				self.currentPackets = scapy.plist.PacketList()
				self.maxPagesIndex = int(self.dbNumRows/1000)
				self.spinPageNum.setMaximum(self.maxPagesIndex+1)
				self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))
				self.currentPageIndex = 0
				self.currentPacketIndex = 0
				self.packsViewer.clear()
				self.onePackViewer.clear()
				self.hexText.setText("")

				#load the first page
				con = connect("tuff.db")
				cur = con.cursor()
				if self.spinPageNum.value()==1:
					cur.execute("select Date, Time, MACsource, MACdest, IPsource, IPdest, Protocol, len, info, binary from maintable limit 1000")
					for row in cur.fetchall():
						self.onePackProcess(pickle.loads(row[9]), row[0],row[1],row[2],row[3],row[4],row[5],row[6],row[7],row[8])
				else:
					self.spinPageNum.setValue(1)
				con.commit()
				con.close()

			self.save.setEnabled(False)
			self.sendToDB.setEnabled(False)

			if [name for name in os.listdir('/tmp/filter/')] != []:
				os.system("rm /tmp/filter/*")

		else:
			self.filterWindow = FilterWindow()
			if self.currentMode == self.darkmode:
				self.filterWindow.setStyleSheet(self.filterWindowStyleD)
			elif self.currentMode == self.lightmode:
				self.filterWindow.setStyleSheet(self.currentMode)
			self.filterWindow.apply_button.connect(self.filterThreadStart)

	def loadTempDirectories(self, directory):
		#get files names in directory
		self.tempFilesNames = sorted([name for name in os.listdir(f"/tmp/{directory}/")])

		#set and reset
		self.currentPackets = scapy.plist.PacketList()
		self.maxPagesIndex = len(self.tempFilesNames)-1
		self.spinPageNum.setMaximum(self.maxPagesIndex+1)
		self.spinPageNum.setValue(1)
		self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))
		self.currentPageIndex = 0
		self.currentPacketIndex = 0
		self.packsViewer.clear()
		self.onePackViewer.clear()
		self.hexText.setText("")
		self.save.setEnabled(False)
		self.sendToDB.setEnabled(False)

		#show the first file
		pList = rdpcap(f"/tmp/{directory}/"+self.tempFilesNames[0])
		for pack in pList:
			self.onePackProcess(pack)

	def filterThreadStart(self, filterStr):
		#show string in the filterSeachBar
		self.filterSearchBar.setText(filterStr)

		self.loadingGifStart("Filtering")

		if filterStr != "":

			if self.currentMode == self.darkmode:
				self.filter.setStyleSheet(self.QPushButtonActiveD)
			elif self.currentMode == self.lightmode:
				self.filter.setStyleSheet(self.QPushButtonActiveL)
			self.filterStatus = True
			self.filterStr = filterStr

			self.maxPagesIndex = 0
			self.tempFilesNames = []
			self.currentPageIndex = 0
			self.currentPacketIndex = 0
			self.currentPackets = scapy.plist.PacketList()
			self.packsViewer.clear()
			self.onePackViewer.clear()
			self.hexText.setText("")
			self.totalNumPage.setText("/ "+str(self.maxPagesIndex+1))

			self.filterThread = FilterThread(self.openedFileName, self.saveLiveFileName, self.save.isEnabled(), self.filterStr)
			self.filterThread.start()
			self.filterThread.filterSnifferFinishedSignal.connect(self.filterSnifferFinished)
			self.filterThread.loadingGifStop.connect(self.loadingGifStop)
		
		else:
			self.loadingGifStop("Invalid Filter!")

	def loadingGifStop(self, msg):
		self.loadingText.setText(msg)
		self.loadingGif.hide()

	def loadingGifStart(self, loadingText):
		self.loadingText.setText(loadingText)
		self.loadingText.show()
		self.loadingGif.show()

	def filterSnifferFinished(self, filterFileNames, ipsList):
		#loadingGIF stop
		self.loadingGifStop("Done Filtering!")

		self.tempFilesNames = filterFileNames
		self.ipsList = ipsList

		if self.tempFilesNames != []:
			#set and reset (filter on)
			self.currentPageIndex = 0
			self.currentPacketIndex = 0
			self.packsViewer.clear()
			self.onePackViewer.clear()
			self.hexText.setText("")
			self.totalNumPage.setText("/ "+str(len(self.tempFilesNames)))
			self.save.setEnabled(True)
			self.sendToDB.setEnabled(True)
			self.spinPageNum.setMaximum(len(self.tempFilesNames))
			self.spinPageNum.setValue(1)
			self.currentPackets = scapy.plist.PacketList()

			pList = rdpcap("/tmp/filter/"+self.tempFilesNames[-1])
			for pack in pList:
				self.currentPackets.append(pack)

			self.numDisplayed.setText(f"Displayed: {1000*(len(self.tempFilesNames)-1)+len(self.currentPackets)}")

			#open the first filter file
			filterTempFiles = sorted([name for name in os.listdir(f"/tmp/filter/")])
			pList = rdpcap("/tmp/filter/"+self.tempFilesNames[0])
			self.dbSideStatus = False
			for pack in pList:
				self.onePackProcess(pack)
			if not self.dbSide.isEnabled():
				self.dbSideStatus = True
		else:
			self.numDisplayed.setText("Displayed: 0")

	def closeEvent(self, event):
		try:
			if self.liveToDB.isRunning():
				self.liveToDB.terminate()
		except:pass
		try:
			if self.createDBtempFiles.isRunning():
				self.createDBtempFiles.terminate()
		except: pass
		try:
			if self.filterThread.filterSniffer.isRunning():
				self.filterThread.filterSniffer.terminate()
		except: pass
		try:
			if self.filterThread.isRunning():
				self.filterThread.terminate()
		except: pass
		try:
			if self.snifferThread.isRunning():
				self.snifferThread.terminate()
		except: pass
		try:
			if self.openThread.filterSniffer.isRunning():
				self.openThread.filterSniffer.terminate()
		except: pass
		try: self.openThread.op.kill()
		except: pass
		try:
			if self.openThread.isRunning():
				self.openThread.terminate()
		except: pass
		try:
			if self.filterSniffer.isRunning():
				self.filterSniffer.terminate()
		except: pass
		try:
			if self.CreateDbTempFileThread.isRunning():
				self.CreateDbTempFileThread.terminate()
		except: pass
		try:
			if self.DeleteFromDbThread.isRunning():
				self.DeleteFromDbThread.terminate()
		except: pass	
		try:
			if self.SendToDBThread.isRunning():
				self.SendToDBThread.terminate()
		except: pass	
		self.removeTempFiles()
		os.system("rmdir /tmp/filter")
		os.system("rmdir /tmp/live")
		os.system("rmdir /tmp/open")
		os.system("rmdir /tmp/db")
		event.accept()

class DeleteFromDbThread(QThread):

	def __init__(self, filterStatus):
		super().__init__()
		self.filterStatus = filterStatus

	def run(self):
		con = connect("tuff.db")
		cur = con.cursor()

		if self.filterStatus:
			filterTempFiles = sorted([name for name in os.listdir(f"/tmp/filter/")])
			for name in filterTempFiles:
				for pack in rdpcap("/tmp/filter/"+name):
					cur.execute("delete from maintable where hexdump=?;", (self.showOutput(pack, "hexdump(pack)"),))
		else:
			cur.execute("delete from maintable")

		con.commit()
		con.close()

	def showOutput(self, pack, expression):
		#Redirect output on the screen to variable 'capture'
		capture = StringIO()
		save_stdout = sys.stdout
		sys.stdout = capture
		eval(expression)
		sys.stdout = save_stdout
		#capture.getvalue() is a string with the output of 'pack.show()' 
		return capture.getvalue()

class SendToDBThread(QThread):
	def __init__(self, tempDir):
		super().__init__()
		self.tempDir = tempDir

	def run(self):
		con = connect('tuff.db')
		cur = con.cursor()

		tempFiles = sorted([name for name in os.listdir(f'/tmp/{self.tempDir}/')])

		for file in tempFiles:
			tempFile = rdpcap(f"/tmp/{self.tempDir}/"+file)
			for pack in tempFile:
				#get date and time
				packDateTime = datetime.datetime.strptime(time.ctime(int(pack.time))[4:], '%b %d %H:%M:%S %Y')
				Date = packDateTime.strftime("%d-%m-%Y")
				Time = packDateTime.strftime("%H:%M:%S")

				#get src and dst
				if pack.haslayer(IP):
					ipsrc = pack[IP].src
					ipdst = pack[IP].dst
				else:
					ipsrc = "NULL"
					ipdst = "NULL"

				if pack.haslayer(Ether):
					macsrc = pack.src
					macdst = pack.dst
				else:
					macsrc = "NULL"
					macdst = "NULL"

				#get protocol
				packSummary = pack.summary()[7:]
				if "Raw" in packSummary:	
					packSummary = packSummary[:-6]
				elif "Padding" in packSummary:
					packSummary = packSummary[:-10]
				packSummaryLst = packSummary.split("/")
				if "igmp" in packSummaryLst[-1]:
					proto = "IGMP"
				else:
					proto = packSummaryLst[-1].split(" ")[1]
				binary = pickle.dumps(pack)
				cur.execute("insert into maintable (Date, Time, MACsource, MACdest, IPsource, IPdest, Protocol, len, info, binary, hexdump) values (?,?,?,?,?,?,?,?,?,?,?)",(Date, Time, macsrc, macdst, ipsrc, ipdst, proto, len(pack), packSummary, binary, self.showOutput(pack, "hexdump(pack)")))

		con.commit()
		con.close()

	def showOutput(self, pack, expression):
		#Redirect output on the screen to variable 'capture'
		capture = StringIO()
		save_stdout = sys.stdout
		sys.stdout = capture
		eval(expression)
		sys.stdout = save_stdout
		#capture.getvalue() is a string with the output of 'pack.show()' 
		return capture.getvalue()

class CreateDbTempFileThread(QThread):

	sendIpsList = pyqtSignal(list)

	def __init__(self):
		super().__init__()

		self.currentPackets = scapy.plist.PacketList()
		self.currentPacketIndex = 0
		self.maxPagesIndex = 0
		self.filterTempFilesNames = []
		self.ipsList = []

	def run(self):
		con = connect("tuff.db")
		cur = con.cursor()

		cur.execute("select binary from maintable")
		for row in cur.fetchall():
			pack = pickle.loads(row[0])
			try:
				if pack[IP].src not in self.ipsList:
					self.ipsList.append(pack[IP].src)
				if pack[IP].dst not in self.ipsList:
					self.ipsList.append(pack[IP].dst)
			except:
				pass
			self.currentPackets.append(pack)
			if self.currentPacketIndex == 1000:
				self.createDBtempFiles()
			self.currentPacketIndex+=1
		self.createDBtempFiles()

		if self.filterTempFilesNames != []:
			files = " ".join(["/tmp/db/"+name for name in self.filterTempFilesNames])
			os.system(f"mergecap -w /tmp/temp_db.cap {files}")

			os.system("rm /tmp/db/*")

		con.commit()
		con.close()

		self.sendIpsList.emit(self.ipsList)

	def createDBtempFiles(self):
		newFilterFileName = f"temp_{str(self.maxPagesIndex).zfill(5)}.cap"
		self.filterTempFilesNames.append(newFilterFileName)
		wrpcap(f"/tmp/db/{newFilterFileName}", self.currentPackets[:1000])
		self.maxPagesIndex += 1
		self.currentPackets = self.currentPackets[1000:]
		self.currentPacketIndex = 0
		self.currentPackets = scapy.plist.PacketList()

class FilterThread(QThread):

	conf1 = pyqtSignal()
	sendFilterSniffedPack = pyqtSignal(Ether)
	filterSnifferFinishedSignal = pyqtSignal(list, list)
	loadingGifStop = pyqtSignal(str)

	def __init__(self,openedFileName, saveLiveFileName, saveStatus,filterStr):
		super().__init__()
		self.openedFileName = openedFileName
		self.saveLiveFileName = saveLiveFileName
		self.saveStatus = saveStatus
		self.filterStr = filterStr

	def run(self):
		if "temp_db.cap" in [name for name in os.listdir(f"/tmp/")]:
			self.filteringFiles("/tmp/temp_db.cap")
		elif self.openedFileName != "": #if a file is opened
			self.filteringFiles(self.openedFileName)
		elif self.saveLiveFileName != "": #if a live file is saved
			self.filteringFiles(self.saveLiveFileName)
		elif "temp_live.cap" in [name for name in os.listdir(f"/tmp/")]: #if a live file is not saved + merged in temp
			self.filteringFiles("/tmp/temp_live.cap")
		elif [name for name in os.listdir(f"/tmp/live/")]!=[]: #if a live files exist and not merged in temp
			liveFiles = sorted([name for name in os.listdir(f"/tmp/live/")])
			files = " ".join(["/tmp/live/"+name for name in liveFiles])
			os.system(f"mergecap -w /tmp/temp_live.cap {files}")
			self.filteringFiles("/tmp/temp_live.cap")
		else:
			self.loadingGifStop.emit("No Data To Filter ...")

	def filteringFiles(self, fileName):
		self.filterSniffer = FilterSniffer(fileName, self.filterStr)
		self.filterSniffer.start()
		self.filterSniffer.sendFilterFileNames.connect(self.filterSnifferFinished)

	def filterSnifferFinished(self, filterFileNames, ipsList):
		self.filterSnifferFinishedSignal.emit(filterFileNames, ipsList)

class SnifferThread(QThread):
	sendPackSignal = pyqtSignal(Ether)
	def __init__(self, iface, filterStr):
		super().__init__()
		self.iface = iface
		self.filterStr = filterStr

	def run(self):
		dateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d))(?: and)?")
		dateToDateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)) to (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)(?: and)?")

		dateAndList = re.findall(dateAndPattern, self.filterStr)
		dateToDateAndList = re.findall(dateToDateAndPattern, self.filterStr)

		if dateToDateAndList!=[]:
			if len(dateToDateAndList)==1:
				self.filterStr=" and ".join(list(filter(None,self.filterStr.split(dateToDateAndList[0]))))
				datePattern = re.compile(r"([0-9]|0[1-9]|[12][0-9]|3[01])-([0-9]|0[1-9]|1[012])-(19\d\d|20\d\d)")
				dateList = re.findall(datePattern, dateToDateAndList[0])
				self.filterDate = f"{dateList[0][0].zfill(2)}-{dateList[0][1].zfill(2)}-{dateList[0][2]}"+" to "+f"{dateList[1][0].zfill(2)}-{dateList[1][1].zfill(2)}-{dateList[1][2]}"
		elif dateAndList!=[]:
			if len(dateAndList)==1:
				self.filterStr=" and ".join(list(filter(None,self.filterStr.split(dateAndList[0]))))
				datePattern = re.compile(r"([0-9]|0[1-9]|[12][0-9]|3[01])-([0-9]|0[1-9]|1[012])-(19\d\d|20\d\d)")
				dateList = re.findall(datePattern, dateAndList[0])
				self.filterDate = f"{dateList[0][0].zfill(2)}-{dateList[0][1].zfill(2)}-{dateList[0][2]}"

		sniff(iface=self.iface, prn = self.sendPack, filter=self.filterStr)
		
	def sendPack(self, pack):
		self.sendPackSignal.emit(pack)

class OpenThread(QThread):

	filterOnSetAndReset = pyqtSignal()
	showOpenedFile = pyqtSignal(list)
	configurePacketsDisplayed = pyqtSignal(str,str)
	filterSnifferFinishedSignal = pyqtSignal(list, list)
	loadingGifStart = pyqtSignal()

	def __init__(self, openedFileName, filterStatus, filterStr):
		super().__init__()
		self.openedFileName = openedFileName
		self.filterStatus = filterStatus
		self.filterStr = filterStr

	def run(self):
		
		self.op = subprocess.Popen(["editcap","-c","1000",self.openedFileName,"/tmp/open/temp.cap"])
		self.op.communicate()

		if self.filterStatus: #in case the file is oppened and filter is activated
			
			self.loadingGifStart.emit()

			self.filterSniffer = FilterSniffer(self.openedFileName, self.filterStr)
			self.filterSniffer.start()
			self.filterSniffer.sendFilterFileNames.connect(self.filterSnifferFinished)

		else:
			#split opened file to temporary captured files with 1000 packets each
			self.tempFilesNames = sorted([name for name in os.listdir('/tmp/open/')])

			#set and reset (filter off)
			self.showOpenedFile.emit(self.tempFilesNames)

		openTempFiles=sorted([name for name in os.listdir(f"/tmp/open/")])
		filterTempFiles=sorted([name for name in os.listdir(f"/tmp/filter/")])
		if self.filterStatus and filterTempFiles!=[]:
			lastOpenFile = sniff(offline="/tmp/open/"+openTempFiles[-1])
			lastFilterFile = sniff(offline="/tmp/filter/"+filterTempFiles[-1])
			self.configurePacketsDisplayed.emit(f"Packets: {1000*(len(openTempFiles)-1)+len(lastOpenFile)}",f"Displayed: {1000*(len(filterTempFiles)-1)+len(lastFilterFile)}")
		elif openTempFiles != []:
			lastFile = sniff(offline="/tmp/open/"+openTempFiles[-1])
			self.configurePacketsDisplayed.emit(f"Packets: {1000*(len(openTempFiles)-1)+len(lastFile)}",f"Displayed: {1000*(len(openTempFiles)-1)+len(lastFile)}")

	def transmitPack(self, pack):
		self.sendFilterSniffedPack.emit(pack)

	def filterSnifferFinished(self, filterFileNames, ipsList):
		self.filterSnifferFinishedSignal.emit(filterFileNames, ipsList)

class FilterSniffer(QThread):

	# filterSnifferSendPack=pyqtSignal(Ether)
	sendFilterFileNames = pyqtSignal(list,list)

	def __init__(self, fileNameOrPack, filterStr):
		super().__init__()
		self.fileNameOrPack = fileNameOrPack

		self.filterTempFilesNames = []
		self.currentPackets = scapy.plist.PacketList()
		self.currentPacketIndex = 0
		self.maxPagesIndex = 0
		self.ipsList = []

		#parsing filter str/date
		self.filterStr = filterStr

		dateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d))(?: and)?")
		dateToDateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)) to (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)(?: and)?")

		dateAndList = re.findall(dateAndPattern, self.filterStr)
		dateToDateAndList = re.findall(dateToDateAndPattern, self.filterStr)

		if dateToDateAndList!=[]:
			if len(dateToDateAndList)==1:
				self.filterStr=" and ".join(list(filter(None,self.filterStr.split(dateToDateAndList[0]))))
				datePattern = re.compile(r"([0-9]|0[1-9]|[12][0-9]|3[01])-([0-9]|0[1-9]|1[012])-(19\d\d|20\d\d)")
				dateList = re.findall(datePattern, dateToDateAndList[0])
				self.filterDate = f"{dateList[0][0].zfill(2)}-{dateList[0][1].zfill(2)}-{dateList[0][2]}"+" to "+f"{dateList[1][0].zfill(2)}-{dateList[1][1].zfill(2)}-{dateList[1][2]}"
		elif dateAndList!=[]:
			if len(dateAndList)==1:
				self.filterStr=" and ".join(list(filter(None,self.filterStr.split(dateAndList[0]))))
				datePattern = re.compile(r"([0-9]|0[1-9]|[12][0-9]|3[01])-([0-9]|0[1-9]|1[012])-(19\d\d|20\d\d)")
				dateList = re.findall(datePattern, dateAndList[0])
				self.filterDate = f"{dateList[0][0].zfill(2)}-{dateList[0][1].zfill(2)}-{dateList[0][2]}"
		else:
			self.filterDate = ""

	def run(self):
		sniff(offline=self.fileNameOrPack, filter=self.filterStr, prn=lambda x:self.processPack(x))
		#create the last filter temp file
		if list(self.currentPackets) != []:
			lastFilterFileName = f"temp_{str(self.maxPagesIndex).zfill(5)}.cap"
			self.filterTempFilesNames.append(lastFilterFileName)
			wrpcap(f"/tmp/filter/{lastFilterFileName}", self.currentPackets)

		self.sendFilterFileNames.emit(self.filterTempFilesNames, self.ipsList)

	def processPack(self, pack):
		Date = datetime.datetime.strptime(time.ctime(int(pack.time))[4:], '%b %d %H:%M:%S %Y')

		if self.filterDate!="":
			if len(self.filterDate.split(" "))>=3:
				Date1 = self.filterDate.split(" ")[0].split("-")
				datetime1 = datetime.datetime(int(Date1[2]), int(Date1[1]), int(Date1[0]))
				Date2 = self.filterDate.split(" ")[2].split("-")
				datetime2 = datetime.datetime(int(Date2[2]), int(Date2[1]), int(Date2[0]))
			elif len(self.filterDate.split(" "))==1:
				Date1 = self.filterDate.split(" ")[0].split("-")
				datetime1 = datetime.datetime(int(Date1[2]), int(Date1[1]), int(Date1[0]))

		try:
			if (datetime2 >= Date and Date >= datetime1):
				self.currentPackets.append(pack)
			else:
				return
		except:
			try:
				if datetime1.date() == Date.date():
					self.currentPackets.append(pack)
				else:
					return
			except:
				if self.filterDate=="":
					self.currentPackets.append(pack)
				else:
					return

		try:
			if pack[IP].src not in self.ipsList:
				self.ipsList.append(pack[IP].src)
			if pack[IP].dst not in self.ipsList:
				self.ipsList.append(pack[IP].dst)
		except:
			pass

		if self.currentPacketIndex == 1000:
			newFilterFileName = f"temp_{str(self.maxPagesIndex).zfill(5)}.cap"
			self.filterTempFilesNames.append(newFilterFileName)
			wrpcap(f"/tmp/filter/{newFilterFileName}", self.currentPackets[:1000])
			self.maxPagesIndex += 1
			self.currentPacketIndex = 0
			self.currentPackets = self.currentPackets[1000:]

		self.currentPacketIndex+=1


if __name__ == "__main__":
	app = QApplication(sys.argv)
	mainWindow = TuffCapture()
	sys.exit(app.exec_())