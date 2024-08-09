import os, json, csv
from db import Database
from config import DATABASE_URI, MODEL_PATH
from embeddings import E5EmbeddingModel
import asyncio

cwe_numbers = {0, 16, 18, 20, 22, 78, 79, 81, 89, 90, 91, 94, 200, 201, 233, 264, 295, 310, 319, 326,
345, 352, 359, 434, 436, 444, 523, 524, 525, 530, 540, 565, 598, 601, 610, 614, 642, 643, 693, 829,
918, 933, 942}

base_dir = '/Users/avishnuv/cvelistV5/cves'
cwe_dir = '/Users/avishnuv/Downloads/cwe.csv'

def process_json_file(file_path, cwe_dict):
    with open(file_path, 'r') as file:
        data = json.load(file)

        try: 
            cwe_id = None
            cwe_name = None
            cve_id = None
            cve_description = None

            containers = data.get('containers')
            cna = containers.get('cna')
            descriptions = cna.get('descriptions')

            #cve_description (equal to descriptions_value)
            for value in descriptions:
                cve_description = value['value']

            problemTypes = cna.get("problemTypes")

            for problem in problemTypes:
                problemTypes_descriptions = problem.get('descriptions')

                #cwe-id (equal to problemTypes_descriptions_cweId, we only want the numbers)
                for desc in problemTypes_descriptions:
                    cwe = desc.get('cweId')
                    cwe_id = cwe[4:]
                    if int(cwe_id) not in cwe_numbers: return

                    #cwe-name (derive from cwe-description)
                    cwe_name = cwe_dict[cwe_id]
            
            #cve-id
            cveMetadata = data.get('cveMetadata')  
            cve_id = cveMetadata.get('cveId')[4:]

            return cwe_id, cwe_name, cve_id, cve_description  

        except Exception as e: return

async def ingest(directory):
    cwe_dict = {}
    embedding_model = E5EmbeddingModel(MODEL_PATH)
    cwe_list = set()
    failure_counter = 0 
    
    db = Database(DATABASE_URI, embedding_model)

    with open(cwe_dir, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = row['cwe_id']
            value = row['cwe_name']
            cwe_dict[key] = value

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)

                entry = process_json_file(file_path, cwe_dict)
                
                if entry:
                    #print(entry)
                    
                    cwe_id, cwe_name, cve_id, cve_description = entry

                    try: 

                        if cwe_id and cve_id and cve_description:
                        
                            if (cwe_id not in cwe_list): 
                                cwe_list.add(cwe_id)

                                await db.insert_cwe(cwe_id, cwe_name)
                        
                            await db.insert_cve(cwe_id, cve_id, cve_description)
                    
                    except:

                        failure_counter += 1
                        print(f"failure counter: {failure_counter}")

if __name__ == '__main__':
    asyncio.run(ingest(base_dir))