SAW?=saw

all: Add.class add.saw
	${SAW} add.saw

%.class: %.java
	javac -g $<

clean:
	rm -f Add.class
