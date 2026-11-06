import math, sys
from fontTools.ttLib import TTFont
from fontTools.pens.basePen import BasePen
from shapely.geometry import Polygon, MultiPolygon
from shapely.ops import unary_union
from shapely import affinity
import shapely

FONT = sys.argv[1]
OUT = sys.argv[2]

class PolyPen(BasePen):
    def __init__(self, gs):
        super().__init__(gs); self.rings=[]; self.cur=[]
    def _moveTo(self,p): self.cur=[p]
    def _lineTo(self,p): self.cur.append(p)
    def _curveToOne(self,p1,p2,p3):
        p0=self.cur[-1]
        for i in range(1,13):
            t=i/12; u=1-t
            x=u*u*u*p0[0]+3*u*u*t*p1[0]+3*u*t*t*p2[0]+t*t*t*p3[0]
            y=u*u*u*p0[1]+3*u*u*t*p1[1]+3*u*t*t*p2[1]+t*t*t*p3[1]
            self.cur.append((x,y))
    def _closePath(self):
        if len(self.cur)>2: self.rings.append(self.cur)
        self.cur=[]
    def _endPath(self): self._closePath()

font=TTFont(FONT); gs=font.getGlyphSet(); cmap=font.getBestCmap(); hmtx=font['hmtx']
upm=font['head'].unitsPerEm

def glyph_poly(ch):
    g=cmap[ord(ch)]; pen=PolyPen(gs); gs[g].draw(pen)
    rings=[Polygon(r).buffer(0) for r in pen.rings]
    # even-odd style union: outer minus inner
    rings.sort(key=lambda p:-p.area)
    geom=rings[0]
    for r in rings[1:]:
        geom = geom.symmetric_difference(r)
    return geom, hmtx[g][0]

def word(text, tracking=-0.06, weight=0.0):
    """returns list of (char, polygon) in font units, y up, baseline 0"""
    x=0; out=[]
    for ch in text:
        p,adv=glyph_poly(ch)
        if ch=='I':
            b=p.bounds; p=affinity.scale(p, 1.7, 1, origin=((b[0]+b[2])/2,0)); adv=int(adv*1.7)
        p=affinity.translate(p, xoff=x)
        if weight: p=p.buffer(weight*upm, join_style='mitre')
        out.append((ch,p)); x+=adv+tracking*upm
    return out

def rounded(p, r):
    return p.buffer(-r, join_style='round').buffer(2*r, join_style='round').buffer(-r, join_style='round')

def warp(p, f, seg=8):
    p=shapely.segmentize(p, seg)
    return shapely.transform(p, lambda a: f(a))

def path_d(p, flip=False, prec=1):
    polys = p.geoms if isinstance(p, MultiPolygon) else [p]
    d=[]
    p=shapely.simplify(p, 0.8)
    polys = p.geoms if isinstance(p, MultiPolygon) else [p]
    for poly in polys:
        for ring in [poly.exterior]+list(poly.interiors):
            pts=list(ring.coords)
            d.append('M'+' '.join(f'{x:.{prec}f},{(-y if flip else y):.{prec}f}' for x,y in pts)+'Z')
    return ' '.join(d)

def bounds(ps):
    return unary_union(ps).bounds

def svg(width, height, body, extra_defs=''):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" width="1000" height="{1000*height/width:.0f}">
<defs>{extra_defs}</defs>
{body}
</svg>'''

import numpy as np
def FT(p, dx, dy):
    return affinity.translate(affinity.scale(p,1,-1,origin=(0,0)), dx, dy)


# ---------- common base: tight, heavy CASIO ----------
base = word("CASIO", tracking=0.045, weight=0.045)
minx,miny,maxx,maxy = bounds([p for _,p in base])
W=maxx-minx; H=maxy-miny
# normalise to y in [0,H] baseline shift
base=[(c, affinity.translate(p, -minx, -miny)) for c,p in base]

# =====================================================================
# OPTION 1 : "Thumb-pressed"  -- squashed flat, bulging out sideways
# =====================================================================
def opt1():
    cx=W/2
    def f(a):
        x=a[:,0]; y=a[:,1]
        ny=y/H  # 0..1
        # squash vertically to 62%, keep baseline, bulge horizontally most at mid-height
        bulge = 1 + 0.09*(1-(2*ny-1)**2)
        # extra sag: letters spread more at the bottom (resting on a surface)
        bulge += 0.03*(1-ny)
        nx = cx + (x-cx)*bulge
        return np.column_stack([nx, y*0.62])
    letters=[]
    for i,(c,p) in enumerate(base):
        p=affinity.translate(p, -i*70, 0)   # tighter, like the original wordmark
        p=rounded(p, 28)
        p=warp(p,f)
        letters.append((c,p))
    allp=unary_union([p for _,p in letters])
    bx0,by0,bx1,by1=allp.bounds
    pad=60
    Wd=bx1-bx0+2*pad; Hd=by1-by0+2*pad+40
    shift=lambda p: affinity.translate(p, -bx0+pad, 0)
    TT=lambda p: FT(p, 0, by1+pad)
    body=[]
    # flat contact shadow under the squished word
    body.append(f'<ellipse cx="{Wd/2:.0f}" cy="{pad+(by1-by0)+8:.0f}" rx="{(bx1-bx0)/2+10:.0f}" ry="26" fill="#1b2a5a" opacity="0.18"/>')
    body.append('<g id="outline" fill="#1b3a8f">')
    for c,p in letters:
        p=shift(p)
        d=path_d(TT(p))
        body.append(f'<path id="{c}" fill-rule="evenodd" d="{d}"/>')
    body.append('</g>')
    # soft top highlight band (pressed, glossy)
    body.append('<g id="shading" fill="#ffffff" opacity="0.28">')
    for c,p in letters:
        p=shift(p)
        lx0,ly0,lx1,ly1=p.bounds
        band=shapely.box(lx0-5, ly0+(ly1-ly0)*0.62, lx1+5, ly1+5)
        hl=p.buffer(-22).intersection(band)
        if not hl.is_empty:
            body.append(f'<path fill-rule="evenodd" d="{path_d(TT(hl))}"/>')
    body.append('</g>')
    return svg(Wd,Hd,'\n'.join(body))

# =====================================================================
# OPTION 2 : "Jelly bounce" -- blobby letters tumbling on a wavy baseline
# =====================================================================
def opt2():
    cols=['#ff5d8f','#ffb703','#06d6a0','#4cc9f0','#b388ff']
    rots=[-9, 6, -5, 8, -7]
    scl =[1.02, 0.96, 1.05, 0.92, 1.08]
    dy  =[0, 90, -60, 70, -40]
    letters=[]
    for i,(c,p) in enumerate(base):
        p=rounded(p, 70)              # very blobby
        # jelly bulge: fatter in the middle, slightly flattened bottom
        cx0,cy0,cx1,cy1=p.bounds; mx=(cx0+cx1)/2
        def f(a, mx=mx):
            x=a[:,0]; y=a[:,1]; ny=(y-cy0)/(cy1-cy0)
            b=1+0.12*np.sin(np.pi*ny)
            return np.column_stack([mx+(x-mx)*b, y])
        p=warp(p,f)
        p=affinity.scale(p, scl[i], scl[i], origin=(mx,cy0))
        p=affinity.rotate(p, rots[i], origin=(mx,(cy0+cy1)/2))
        p=affinity.translate(p, -i*25, dy[i])      # overlap neighbours a bit
        letters.append((c,p,cols[i]))
    allp=unary_union([p for _,p,_ in letters]); bx0,by0,bx1,by1=allp.bounds
    pad=70; Wd=bx1-bx0+2*pad; Hd=by1-by0+2*pad
    T=lambda p: FT(p, -bx0+pad, by1+pad)
    body=['<g id="shadow" fill="#2b1d3a" opacity="0.22">']
    for c,p,col in letters:
        body.append(f'<path fill-rule="evenodd" d="{path_d(T(affinity.translate(p,10,-14)))}"/>')
    body.append('</g><g id="outline">')
    for c,p,col in sorted(letters, key=lambda t: t[0]=='I'):
        body.append(f'<path id="{c}" fill="{col}" stroke="#2b1d3a" stroke-width="12" stroke-linejoin="round" fill-rule="evenodd" d="{path_d(T(p))}"/>')
    body.append('</g><g id="shading" fill="#ffffff" opacity="0.55">')
    for c,p,col in letters:
        # gloss: an upper-left blob clipped to the letter
        cx0,cy0,cx1,cy1=p.bounds
        gl=affinity.scale(shapely.Point((cx0+cx1)/2-(cx1-cx0)*0.18,(cy0+cy1)/2+(cy1-cy0)*0.25).buffer((cx1-cx0)*0.26), 1.3, 0.55)
        gl=gl.intersection(p.buffer(-22))
        if not gl.is_empty: body.append(f'<path fill-rule="evenodd" d="{path_d(T(gl))}"/>')
    body.append('</g>')
    return svg(Wd,Hd,'\n'.join(body))

# =====================================================================
# OPTION 3 : "Pillow puff" -- inflated, overlapping, with stitched seam
# =====================================================================
def opt3():
    letters=[]
    for c,p in base:
        p=p.buffer(55, join_style='round')     # inflate
        p=rounded(p, 40)
        # puff: balloon-shaped bulge, widest at 55% height
        cx0,cy0,cx1,cy1=p.bounds; mx=(cx0+cx1)/2
        def f(a, mx=mx):
            x=a[:,0]; y=a[:,1]; ny=(y-cy0)/(cy1-cy0)
            b=1+0.10*np.sin(np.pi*ny**0.8)
            return np.column_stack([mx+(x-mx)*b, cy0+(y-cy0)*(1+0.06*np.sin(np.pi*ny))])
        p=warp(p,f)
        letters.append((c,p))
    # pack tighter so they squash into each other
    packed=[]; x=0
    for i,(c,p) in enumerate(letters):
        p=affinity.translate(p, -i*60, 0)
        packed.append((c,p))
    letters=packed
    allp=unary_union([p for _,p in letters]); bx0,by0,bx1,by1=allp.bounds
    pad=70; Wd=bx1-bx0+2*pad; Hd=by1-by0+2*pad
    T=lambda p: FT(p, -bx0+pad, by1+pad)
    defs='''<radialGradient id="puff" cx="40%" cy="30%" r="80%"><stop offset="0" stop-color="#ffd6e0"/><stop offset="0.55" stop-color="#ff7aa2"/><stop offset="1" stop-color="#d6336c"/></radialGradient>'''
    body=['<g id="shadow" fill="#5c1e36" opacity="0.25">']
    body.append(f'<path fill-rule="evenodd" d="{path_d(T(affinity.translate(allp.buffer(6),0,-22)))}"/>')
    body.append('</g><g id="outline">')
    # draw back-to-front so each letter sits on the previous one; cut a seam gap into the one behind
    for i,(c,p) in enumerate(letters):
        shape=p
        if i+1 < len(letters):
            shape=shape.difference(letters[i+1][1].buffer(16))   # gap where next letter overlaps
        body.append(f'<path id="{c}" fill="url(#puff)" fill-rule="evenodd" d="{path_d(T(shape))}"/>')
    body.append('</g><g id="seam" fill="none" stroke="#7a1f44" stroke-width="7" stroke-dasharray="26 22" stroke-linecap="round" opacity="0.7">')
    for c,p in letters:
        inner=p.buffer(-48)
        if not inner.is_empty: body.append(f'<path d="{path_d(T(inner))}"/>')
    body.append('</g><g id="shading" fill="#ffffff" opacity="0.5">')
    for c,p in letters:
        cx0,cy0,cx1,cy1=p.bounds
        gl=affinity.scale(shapely.Point((cx0+cx1)/2-(cx1-cx0)*0.15,(cy0+cy1)/2+(cy1-cy0)*0.28).buffer((cx1-cx0)*0.2),1.4,0.5)
        gl=gl.intersection(p.buffer(-70))
        if not gl.is_empty: body.append(f'<path fill-rule="evenodd" d="{path_d(T(gl))}"/>')
    body.append('</g>')
    return svg(Wd,Hd,'\n'.join(body), defs)

for name,fn in [('casio-squish-1-thumb-pressed.svg',opt1),('casio-squish-2-jelly-bounce.svg',opt2),('casio-squish-3-pillow-puff.svg',opt3)]:
    s=fn(); open(f'{OUT}/{name}','w').write(s); print(name, len(s))
