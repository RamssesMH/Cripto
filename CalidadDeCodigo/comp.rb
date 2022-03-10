ent=File.read("entrada.txt")

	a=0
	c=0
	q=0
	w=0
	t=0
	y=0
lines = ent.split(" ")
lines.each do |line|

		if line=="("
		a=a+1
		end
		if line==")"
		c=c+1
		end
		if line=="["
		q=q+1
		end
		if line=="]"
		w=w+1
		end
		if line=="{"
		t=t+1
		end
		if line=="}"
		y=y+1
		end
		
		

		if line=="PARA"||line=="MIENTRAS"||line=="ESCRIBE"||line=="SI"||line=="ENTERO"||line=="FLOTANTE"||line=="CARACTER"||line=="CADENA"
		if line=="PARA"
		
		File.write("salida.txt", "for ")
		
		end
	
		if line =="MIENTRAS"
		File.write("salida.txt", "while \n")
		puts "while"
		end
		if line =="ESCRIBE"
		File.write("salida.txt", "System.out.println(" )
		
		lines = ent.split(" ")
		File.write("salida.txt", line )
		File.write("salida.txt", ");" )
		puts "System.out.println("+line+");"
		
		end
		if line =="SI"
		File.write("salida.txt", "if \n")
		puts "si"
		end
		
		if line =="ENTERO"
		File.write("salida.txt", "int \n")
		puts "int"
		end
		
		if line =="FLOTANTE"
		File.write("salida.txt", "float \n")
		puts "float"
		end
		
		if line =="CARACTER"
		File.write("salida.txt", "char \n")
		puts "char"
		end
		
		if line =="CADENA"
		File.write("salida.txt", "String \n")
		puts "String"
		end
		
		
		elsif
		puts line
		end
		
end
if a<c||a>c
		puts "te falto abrir o cerrar algun o algunos parentesis"
		end
		if q<w||q>w
		puts "te falto abrir o cerrar algun o algunos corchetes"
		end
		if t<y||t>y
		puts "te falto abrir o cerrar alguna o algunas llaves"
		end
	gets()