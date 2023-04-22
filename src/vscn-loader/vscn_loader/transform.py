
class CVETransformService(object):

    def transform(self, raw_cves):
        cves = []
        for raw_cve in raw_cves:            
            cve = {}
            
            cve["id"] = raw_cve.get("id")
            cve["source_identifier"] = raw_cve.get("source_identifier")
            cve["published_at"] = raw_cve.get("published_at")
            cve["last_modified_at"] = raw_cve.get("last_modified_at")
            cve["vulnerability_status"] = raw_cve.get("vulnerability_status")
            
            cve["description"] = self._transform_descriptions(raw_cve.get("descriptions", []))
            cve["weaknesses"] = self._transform_weaknesses(raw_cve.get("weaknesses", []))
            cve["refs"] = self._transform_references(raw_cve.get("refs", []))
            
            # TODO: transform metrics
            
            products, vendors, types, configurations = self._transform_configurations(raw_cve.get("configurations", []))
            cve["configurations"] = configurations

            cve["products"] = list(products)
            cve["vendors"] = list(vendors)
            cve["types"] = list(types)
            
            cves.append(cve)
        return cves

    def _transform_descriptions(self, descriptions: list) -> str:
        for description in descriptions:
            if description.get("lang", "") == "en":
                return description.get("value", "")
        return ""

    def _transform_weaknesses(self, raw_weaknesses: list) -> list:
        weaknesses = set()
        for raw_weakness in raw_weaknesses:
            for raw_description in raw_weakness.get("description", []):
                weaknesses.add(raw_description.get("value"))
        return list(weaknesses)

    def _transform_references(self, raw_references: list) -> list:
        references = []
        for raw_reference in raw_references:
            references.append(raw_reference.get("url",""))
        return references
    
    def _transform_configurations(self, raw_configurations: list):
        products = set()
        vendors = set()
        types = set()
        
        configurations = []
        for raw_configuration in raw_configurations:
            nodes = []
            raw_nodes = raw_configuration.get("nodes", [])
            transformed_nodes = self._transform_nodes(raw_nodes, products, vendors, types)
            
            nodes.extend(transformed_nodes)
            configurations.append(nodes)

        return (products, vendors, types, configurations)
    
    def _transform_nodes(self, raw_nodes: list, products: set, vendors: set, types: set) -> list:
        if not raw_nodes:
            return []

        nodes = []
        for raw_node in raw_nodes:
            node = {}
            node["operator"] = raw_node.get("operator", "")
            node["negate"] = raw_node.get("negate", False)
            
            cpe_matches = raw_node.get("cpeMatch", [])
            node["cpeMatch"] = self._transform_cpe_matches(cpe_matches, products, vendors, types)
            
            # children = node["children"]

            # if children:
            #     for child in children:
            #         self._transform_node(child, products, vendors)

            nodes.append(node)
        return nodes


    def _transform_cpe_matches(self, raw_cpe_matches: list, products: set, vendors: set, types: set) -> list:
        
        cpes = []
        
        for raw_cpe in raw_cpe_matches:
            
            # cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
            cpe = {}
            
            criteria = raw_cpe["criteria"]
            cpe["criteria"] = criteria
            
            cpe["vulnerable"] = raw_cpe["vulnerable"]
            cpe_constant, cpe_version, type, vendor, product, exact_version, update, edition, language, sw_edition, target_sw, target_hw, *others  = criteria.split(":")
            
            cpe["type"] = type
            cpe["vendor"] = vendor
            cpe["product"] = product
            cpe["exactVersion"] = exact_version
            cpe["update"] = update
            cpe["target"] = sw_edition # ?
            
            cpe["versionStartIncluding"] = raw_cpe.get("versionStartIncluding")
            cpe["versionEndIncluding"] = raw_cpe.get("versionEndIncluding")
            cpe["versionStartExcluding"] = raw_cpe.get("versionStartExcluding")
            cpe["versionEndExcluding"] = raw_cpe.get("versionEndExcluding")

            products.add(product)
            vendors.add(vendor)
            types.add(type)
            
            cpes.append(cpe)
        
        return cpes