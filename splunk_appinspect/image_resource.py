import os
import dimensions
from file_resource import FileResource


class ImageResource(FileResource):

    def __init__(self, image_path):
        """This only supports PNG/JPEG/GIF image formats, and will thrown NotImplementedError for non supported formats
        """
        FileResource.__init__(self, image_path)
        self.image_path = image_path
        self.meta = dimensions.dimensions([self.image_path])[0]  # workaround for https://github.com/philadams/dimensions/issues/4

    def dimensions(self):
        return self.meta[0:2]

    def is_png(self):
        return self.meta[2] == 'image/png'

    def content_type(self):
        return self.meta[2]
