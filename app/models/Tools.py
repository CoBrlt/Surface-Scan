import re
import openpyxl


def csvTodict(csv:str):

    csv = remove_semicolons_inside_quotes(csv)

    csv = csv.replace("\r", "")

    if csv.endswith("\n"):
         csv = csv[:-1]

    csv_lines = csv.split("\n")
    header = csv_lines[0].split(";")
    del(csv_lines[0])

    data_dict = []
    for i in range(len(csv_lines)):
        elements = csv_lines[i].split(";")
        data_dict.append({})
        for j in range(len(elements)):
                data_dict[i][header[j]] = elements[j]

    return data_dict

def remove_semicolons_inside_quotes(input_string):
    pattern = r'("[^"]*")'
    
    def replace_semicolon(match):
        return match.group(0).replace(';', '')


    output_string = re.sub(pattern, replace_semicolon, input_string)
    
    return output_string

def xlsxToDict(path_xlsx:str)->str:

        workbook = openpyxl.load_workbook(filename=path_xlsx, read_only=True)

        excel = workbook.active
        
        csv = ""

        for row in excel.iter_rows(values_only=True):
            for cell_value in row:
                if cell_value == None:
                    cell_value = ""
                cell_value = str(cell_value).replace(";", " ")
                cell_value = cell_value.replace("\n", "")
                csv += str(cell_value) + ";"
            csv = csv[:-1] + "\n"
        
        workbook.close()

        return csvTodict(csv)

def getIfInDict(keyword:str, dict:dict) -> str:
    if keyword in dict:
        return dict[keyword]
    else:
        return ""