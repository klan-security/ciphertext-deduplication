import os

def File_Reverse(in_filepath, out_filepath = ''):
    with open(in_filepath, 'rb') as f:
        tmp = f.read()
    if not out_filepath:
        in_filepath = os.path.split(in_filepath)
        out_filepath = in_filepath[0] + '/rev_' + in_filepath[1]
    with open(out_filepath, 'wb') as f:
        f.write(tmp[::-1])

if __name__ == "__main__":
    File_Reverse('D://hello.txt')